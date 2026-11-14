//! Clash-compatible rule engine.
//!
//! Rules are evaluated in order and the first match wins. Runs of adjacent
//! rules of the same family with the same policy are merged into one indexed
//! set, so long pasted lists stay fast without changing first-match semantics.
//!
//! Domain rules never need DNS. When evaluation reaches an IP rule for a
//! target that is still a domain (and the rule has no `no-resolve`), it stops
//! with [`Step::NeedsIp`]; the caller resolves the domain and resumes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use anyhow::{bail, Context, Result};
use ipnet::IpNet;

use crate::config::{Profile, RuleSetBehavior, RuleSetConfig, DIRECT};
use crate::geoip::GeoIp;

/// What a rule is evaluated against.
#[derive(Clone, Debug, Default)]
pub struct Query {
    pub domain: Option<String>,
    /// `None` until resolved; `Some(vec![])` when resolution found nothing.
    pub ips: Option<Vec<IpAddr>>,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matched {
    /// The rule as the user would write it, e.g. `DOMAIN-SUFFIX,github.com`.
    pub rule: String,
    pub policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Matched(Matched),
    /// Resolve `query.domain`, fill `query.ips` and call `evaluate` again
    /// with `resume_at`.
    NeedsIp { resume_at: usize },
}

pub struct RuleEngine {
    rules: Vec<Compiled>,
    geoip: Option<Arc<GeoIp>>,
}

struct Compiled {
    set: Arc<Set>,
    policy: String,
    no_resolve: bool,
    /// For rule sets: `RULE-SET,name`; empty for merged inline rules.
    prefix: String,
    is_match_all: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Domain,
    Ip,
    Port,
}

impl RuleEngine {
    /// Compile the profile's rules. Unsupported rule types are skipped and
    /// reported as warnings; unknown policies are errors.
    pub fn compile(profile: &Profile, geoip: Option<Arc<GeoIp>>, base_dir: Option<&Path>) -> Result<(RuleEngine, Vec<String>)> {
        let policies = profile.policy_names();
        let mut warnings = Vec::new();
        let mut rules: Vec<Compiled> = Vec::new();
        // The run being merged: (family, policy, no_resolve, set).
        let mut run: Option<(Family, String, bool, Set)> = None;
        let mut rule_set_cache: HashMap<String, Arc<Set>> = HashMap::new();

        fn flush(run: &mut Option<(Family, String, bool, Set)>, rules: &mut Vec<Compiled>) {
            if let Some((_, policy, no_resolve, mut set)) = run.take() {
                set.finish();
                rules.push(Compiled { set: Arc::new(set), policy, no_resolve, prefix: String::new(), is_match_all: false });
            }
        }

        for (index, raw) in profile.rules.iter().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = || format!("第 {} 条规则“{line}”", index + 1);
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            let kind = parts[0].to_ascii_uppercase();

            if kind == "MATCH" || kind == "FINAL" {
                let policy = parts.get(1).copied().with_context(|| format!("{}：缺少策略", at()))?;
                check_policy(&policies, policy).with_context(at)?;
                flush(&mut run, &mut rules);
                rules.push(Compiled {
                    set: Arc::new(Set::default()),
                    policy: policy.to_string(),
                    no_resolve: true,
                    prefix: "MATCH".into(),
                    is_match_all: true,
                });
                continue;
            }

            if parts.len() < 3 {
                bail!("{}：应为 类型,值,策略", at());
            }
            let (value, policy) = (parts[1], parts[2]);
            let no_resolve = parts[3..].iter().any(|p| p.eq_ignore_ascii_case("no-resolve"));
            check_policy(&policies, policy).with_context(at)?;

            if kind == "RULE-SET" {
                let set = match rule_set_cache.get(value) {
                    Some(set) => set.clone(),
                    None => {
                        let cfg = profile
                            .rule_sets
                            .get(value)
                            .with_context(|| format!("{}：没有名为“{value}”的规则集", at()))?;
                        let set = Arc::new(load_rule_set(cfg, base_dir, &mut warnings).with_context(|| format!("规则集“{value}”"))?);
                        rule_set_cache.insert(value.to_string(), set.clone());
                        set
                    }
                };
                flush(&mut run, &mut rules);
                rules.push(Compiled {
                    set,
                    policy: policy.to_string(),
                    no_resolve,
                    prefix: format!("RULE-SET,{value}"),
                    is_match_all: false,
                });
                continue;
            }

            let mut single = Set::default();
            let family = match single.add(&kind, value) {
                Ok(Some(family)) => family,
                Ok(None) => {
                    warnings.push(format!("{}：暂不支持 {kind}，已跳过", at()));
                    continue;
                }
                Err(e) => return Err(e.context(at())),
            };
            let continues = matches!(&run, Some((f, p, nr, _)) if *f == family && p == policy && *nr == no_resolve);
            if !continues {
                flush(&mut run, &mut rules);
                run = Some((family, policy.to_string(), no_resolve, Set::default()));
            }
            run.as_mut().unwrap().3.merge(single);
        }
        flush(&mut run, &mut rules);

        let needs_geoip = rules.iter().any(|r| r.set.geoip.iter().any(|c| c != "LAN"));
        if needs_geoip && geoip.is_none() {
            warnings.push("有 GEOIP 规则但没有配置 GeoIP 数据库，这些规则不会命中（GEOIP,LAN 除外）".into());
        }
        Ok((RuleEngine { rules, geoip }, warnings))
    }

    /// Evaluate from rule `start`. With no match the result is `DIRECT`.
    pub fn evaluate(&self, query: &Query, start: usize) -> Step {
        for (i, rule) in self.rules.iter().enumerate().skip(start) {
            if rule.is_match_all {
                return Step::Matched(Matched { rule: "MATCH".into(), policy: rule.policy.clone() });
            }
            let set = &rule.set;
            let mut hit = None;
            if let Some(domain) = &query.domain {
                hit = set.match_domain(domain);
            }
            if hit.is_none() {
                hit = set.match_port(query.port);
            }
            if hit.is_none() && set.has_ip_entries() {
                match &query.ips {
                    Some(ips) => hit = set.match_ips(ips, self.geoip.as_deref()),
                    None if query.domain.is_some() && !rule.no_resolve => return Step::NeedsIp { resume_at: i },
                    None => {}
                }
            }
            if let Some(entry) = hit {
                let rule_text = if rule.prefix.is_empty() { entry } else { format!("{}（{entry}）", rule.prefix) };
                return Step::Matched(Matched { rule: rule_text, policy: rule.policy.clone() });
            }
        }
        Step::Matched(Matched { rule: "（没有命中，默认）".into(), policy: DIRECT.into() })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn check_policy(policies: &HashSet<String>, policy: &str) -> Result<()> {
    if policies.contains(policy) {
        Ok(())
    } else {
        bail!("未知策略“{policy}”（可用：DIRECT、REJECT、节点名或策略组名）")
    }
}

/// An indexed collection of rule entries that share one policy.
#[derive(Default)]
pub(crate) struct Set {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keywords: Vec<String>,
    keyword_matcher: Option<AhoCorasick>,
    ips: IpSet,
    geoip: Vec<String>,
    ports: Vec<(u16, u16)>,
}

impl Set {
    /// Add one classical entry. `Ok(None)` means the type is not supported.
    fn add(&mut self, kind: &str, value: &str) -> Result<Option<Family>> {
        let value = value.trim();
        Ok(Some(match kind {
            "DOMAIN" => {
                self.exact.insert(normalize_domain(value)?);
                Family::Domain
            }
            "DOMAIN-SUFFIX" => {
                self.suffix.insert(normalize_domain(value.trim_start_matches('.'))?);
                Family::Domain
            }
            "DOMAIN-KEYWORD" => {
                if value.is_empty() {
                    bail!("关键字不能为空");
                }
                self.keywords.push(value.to_ascii_lowercase());
                Family::Domain
            }
            "IP-CIDR" | "IP-CIDR6" | "IP6-CIDR" => {
                let net: IpNet = value.parse().with_context(|| format!("“{value}”不是有效的网段"))?;
                self.ips.insert(net);
                Family::Ip
            }
            "GEOIP" => {
                if value.is_empty() {
                    bail!("缺少国家代码");
                }
                self.geoip.push(value.to_ascii_uppercase());
                Family::Ip
            }
            "DST-PORT" => {
                for part in value.split('/') {
                    let (lo, hi) = match part.split_once('-') {
                        Some((a, b)) => (a.trim().parse::<u16>()?, b.trim().parse::<u16>()?),
                        None => {
                            let p = part.trim().parse::<u16>().with_context(|| format!("“{part}”不是端口"))?;
                            (p, p)
                        }
                    };
                    if lo > hi {
                        bail!("端口范围 {lo}-{hi} 无效");
                    }
                    self.ports.push((lo, hi));
                }
                Family::Port
            }
            _ => return Ok(None),
        }))
    }

    fn merge(&mut self, other: Set) {
        self.exact.extend(other.exact);
        self.suffix.extend(other.suffix);
        self.keywords.extend(other.keywords);
        self.ips.extend(other.ips);
        self.geoip.extend(other.geoip);
        self.ports.extend(other.ports);
    }

    fn finish(&mut self) {
        self.keywords.sort();
        self.keywords.dedup();
        self.keyword_matcher = if self.keywords.is_empty() { None } else { AhoCorasick::new(&self.keywords).ok() };
        self.ips.finish();
        self.geoip.sort();
        self.geoip.dedup();
    }

    fn match_domain(&self, domain: &str) -> Option<String> {
        if self.exact.contains(domain) {
            return Some(format!("DOMAIN,{domain}"));
        }
        if !self.suffix.is_empty() {
            let mut rest = domain;
            loop {
                if self.suffix.contains(rest) {
                    return Some(format!("DOMAIN-SUFFIX,{rest}"));
                }
                match rest.split_once('.') {
                    Some((_, parent)) => rest = parent,
                    None => break,
                }
            }
        }
        let matcher = self.keyword_matcher.as_ref()?;
        let m = matcher.find(domain)?;
        Some(format!("DOMAIN-KEYWORD,{}", self.keywords[m.pattern().as_usize()]))
    }

    fn match_port(&self, port: u16) -> Option<String> {
        self.ports
            .iter()
            .find(|(lo, hi)| (*lo..=*hi).contains(&port))
            .map(|(lo, hi)| if lo == hi { format!("DST-PORT,{lo}") } else { format!("DST-PORT,{lo}-{hi}") })
    }

    fn has_ip_entries(&self) -> bool {
        !self.ips.is_empty() || !self.geoip.is_empty()
    }

    fn match_ips(&self, ips: &[IpAddr], geoip: Option<&GeoIp>) -> Option<String> {
        for ip in ips {
            if let Some(net) = self.ips.lookup(*ip) {
                return Some(format!("{},{net}", if net.addr().is_ipv4() { "IP-CIDR" } else { "IP-CIDR6" }));
            }
            for code in &self.geoip {
                let hit = if code == "LAN" {
                    is_lan(*ip)
                } else {
                    geoip.and_then(|g| g.country(*ip)).is_some_and(|c| c.eq_ignore_ascii_case(code))
                };
                if hit {
                    return Some(format!("GEOIP,{code}"));
                }
            }
        }
        None
    }
}

fn normalize_domain(value: &str) -> Result<String> {
    let d = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.contains(['/', ' ', ',']) {
        bail!("“{value}”不是有效的域名");
    }
    Ok(d)
}

fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64,
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Disjoint, sorted address ranges for O(log n) lookups.
#[derive(Default)]
struct IpSet {
    nets: Vec<IpNet>,
    v4: Vec<(u32, u32, usize)>,
    v6: Vec<(u128, u128, usize)>,
}

impl IpSet {
    fn insert(&mut self, net: IpNet) {
        self.nets.push(net.trunc());
    }

    fn extend(&mut self, other: IpSet) {
        self.nets.extend(other.nets);
    }

    fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    fn finish(&mut self) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (i, net) in self.nets.iter().enumerate() {
            match net {
                IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()), i)),
                IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()), i)),
            }
        }
        self.v4 = disjoint(v4);
        self.v6 = disjoint(v6);
    }

    fn lookup(&self, ip: IpAddr) -> Option<IpNet> {
        let idx = match ip {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(v6)),
            },
        }?;
        Some(self.nets[idx])
    }
}

/// CIDR blocks either nest or are disjoint, so dropping the nested ones
/// leaves disjoint ranges that a binary search can scan.
fn disjoint<T: Ord + Copy>(mut ranges: Vec<(T, T, usize)>) -> Vec<(T, T, usize)> {
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Vec<(T, T, usize)> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if let Some(last) = out.last() {
            if r.1 <= last.1 {
                continue;
            }
        }
        out.push(r);
    }
    out
}

fn find<T: Ord + Copy>(ranges: &[(T, T, usize)], x: T) -> Option<usize> {
    let pos = ranges.partition_point(|r| r.0 <= x);
    let r = ranges.get(pos.checked_sub(1)?)?;
    (x <= r.1).then_some(r.2)
}

fn load_rule_set(cfg: &RuleSetConfig, base_dir: Option<&Path>, warnings: &mut Vec<String>) -> Result<Set> {
    let path = match base_dir {
        Some(dir) if cfg.path.is_relative() => dir.join(&cfg.path),
        _ => cfg.path.clone(),
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("读取 {}", path.display()))?;
    let entries = parse_rule_set_text(&text)?;
    let mut set = Set::default();
    let mut skipped = 0usize;
    for entry in entries {
        let result = match cfg.behavior {
            RuleSetBehavior::Domain => {
                if let Some(rest) = entry.strip_prefix("+.").or_else(|| entry.strip_prefix("*.")).or_else(|| entry.strip_prefix('.')) {
                    // `*.x` (one level) and `.x` (subdomains only) are treated as
                    // `+.x`; the apex also matching is harmless for routing.
                    set.add("DOMAIN-SUFFIX", rest)
                } else {
                    set.add("DOMAIN", &entry)
                }
            }
            RuleSetBehavior::Ipcidr => set.add("IP-CIDR", &entry),
            RuleSetBehavior::Classical => {
                let mut parts = entry.splitn(3, ',');
                let kind = parts.next().unwrap_or("").trim().to_ascii_uppercase();
                let value = parts.next().unwrap_or("").trim().to_string();
                set.add(&kind, &value)
            }
        };
        match result {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        warnings.push(format!("规则集 {} 中有 {skipped} 条不支持或无法解析，已跳过", path.display()));
    }
    set.finish();
    Ok(set)
}

/// Lines of a text list, or the `payload:` list of a Clash YAML provider.
fn parse_rule_set_text(text: &str) -> Result<Vec<String>> {
    if text.lines().any(|l| l.trim_start().starts_with("payload:")) {
        #[derive(serde::Deserialize)]
        struct Provider {
            payload: Vec<String>,
        }
        let p: Provider = serde_yaml_ng::from_str(text).context("规则集 YAML 格式错误")?;
        return Ok(p.payload.into_iter().map(|s| s.trim().trim_matches('\'').to_string()).collect());
    }
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GroupConfig, GroupKind};

    fn profile(rules: &[&str]) -> Profile {
        Profile {
            groups: vec![GroupConfig { name: "代理".into(), kind: GroupKind::Select, nodes: vec!["DIRECT".into()] }],
            rules: rules.iter().map(|s| s.to_string()).collect(),
            ..Profile::default()
        }
    }

    fn eval(engine: &RuleEngine, domain: Option<&str>, ips: Option<Vec<IpAddr>>, port: u16) -> Step {
        engine.evaluate(&Query { domain: domain.map(str::to_string), ips, port }, 0)
    }

    fn policy(step: Step) -> String {
        match step {
            Step::Matched(m) => m.policy,
            Step::NeedsIp { .. } => panic!("needs ip"),
        }
    }

    #[test]
    fn first_match_wins_across_merged_runs() {
        let p = profile(&[
            "DOMAIN,exact.example.com,REJECT",
            "DOMAIN-SUFFIX,example.com,代理",
            "DOMAIN-KEYWORD,google,代理",
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-SUFFIX,other.example.com,REJECT",
            "MATCH,DIRECT",
        ]);
        let (engine, warnings) = RuleEngine::compile(&p, None, None).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(policy(eval(&engine, Some("exact.example.com"), None, 443)), "REJECT");
        assert_eq!(policy(eval(&engine, Some("a.b.example.com"), None, 443)), "代理");
        assert_eq!(policy(eval(&engine, Some("example.com"), None, 443)), "代理");
        assert_eq!(policy(eval(&engine, Some("notexample.com"), None, 443)), "DIRECT");
        // Earlier suffix rule wins over the later, more specific one.
        assert_eq!(policy(eval(&engine, Some("x.other.example.com"), None, 443)), "代理");
        assert_eq!(policy(eval(&engine, Some("www.google.com.hk"), None, 443)), "代理");
        match eval(&engine, Some("a.example.com"), None, 1) {
            Step::Matched(m) => assert_eq!(m.rule, "DOMAIN-SUFFIX,example.com"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ip_rules_request_resolution_unless_no_resolve() {
        let p = profile(&[
            "DOMAIN-SUFFIX,direct.test,DIRECT",
            "IP-CIDR,10.66.0.0/24,代理,no-resolve",
            "IP-CIDR,8.8.8.0/24,REJECT",
            "IP-CIDR6,2001:db8::/32,REJECT",
            "GEOIP,LAN,DIRECT",
            "MATCH,代理",
        ]);
        let (engine, _) = RuleEngine::compile(&p, None, None).unwrap();
        // no-resolve rule is skipped for domains; the next IP rule needs DNS.
        let step = eval(&engine, Some("dns.google"), None, 443);
        let Step::NeedsIp { resume_at } = step else { panic!("{step:?}") };
        let resolved = Query { domain: Some("dns.google".into()), ips: Some(vec!["8.8.8.8".parse().unwrap()]), port: 443 };
        match engine.evaluate(&resolved, resume_at) {
            Step::Matched(m) => {
                assert_eq!(m.policy, "REJECT");
                assert_eq!(m.rule, "IP-CIDR,8.8.8.0/24");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(policy(eval(&engine, None, Some(vec!["10.66.0.1".parse().unwrap()]), 22)), "代理");
        assert_eq!(policy(eval(&engine, None, Some(vec!["2001:db8::1".parse().unwrap()]), 22)), "REJECT");
        assert_eq!(policy(eval(&engine, None, Some(vec!["192.168.1.5".parse().unwrap()]), 22)), "DIRECT");
        assert_eq!(policy(eval(&engine, None, Some(vec!["1.1.1.1".parse().unwrap()]), 22)), "代理");
        // A domain with an empty resolution falls through to MATCH.
        let empty = Query { domain: Some("nx.test".into()), ips: Some(vec![]), port: 80 };
        assert_eq!(policy(engine.evaluate(&empty, 0)), "代理");
    }

    #[test]
    fn nested_cidrs_and_ports() {
        let p = profile(&[
            "IP-CIDR,10.0.0.0/8,REJECT,no-resolve",
            "IP-CIDR,10.1.0.0/16,REJECT,no-resolve",
            "IP-CIDR,11.0.0.0/8,REJECT,no-resolve",
            "DST-PORT,22/8000-8100,代理",
            "MATCH,DIRECT",
        ]);
        let (engine, _) = RuleEngine::compile(&p, None, None).unwrap();
        for ip in ["10.1.2.3", "10.200.0.1", "11.255.255.255"] {
            assert_eq!(policy(eval(&engine, None, Some(vec![ip.parse().unwrap()]), 1)), "REJECT", "{ip}");
        }
        assert_eq!(policy(eval(&engine, None, Some(vec!["12.0.0.0".parse().unwrap()]), 1)), "DIRECT");
        assert_eq!(policy(eval(&engine, Some("a.test"), None, 8050)), "代理");
        assert_eq!(policy(eval(&engine, Some("a.test"), None, 8101)), "DIRECT");
    }

    #[test]
    fn rule_sets_and_errors() {
        let dir = std::env::temp_dir().join(format!("supernet-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("list.yaml"), "payload:\n  - '+.github.com'\n  - 'example.org'\n").unwrap();
        std::fs::write(dir.join("ips.txt"), "# comment\n1.2.3.0/24\n").unwrap();
        let mut p = profile(&["RULE-SET,gh,代理", "RULE-SET,ips,REJECT,no-resolve", "PROCESS-NAME,curl.exe,REJECT", "MATCH,DIRECT"]);
        p.rule_sets.insert("gh".into(), RuleSetConfig { path: "list.yaml".into(), behavior: RuleSetBehavior::Domain });
        p.rule_sets.insert("ips".into(), RuleSetConfig { path: "ips.txt".into(), behavior: RuleSetBehavior::Ipcidr });
        let (engine, warnings) = RuleEngine::compile(&p, None, Some(&dir)).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        match eval(&engine, Some("api.github.com"), None, 443) {
            Step::Matched(m) => {
                assert_eq!(m.policy, "代理");
                assert_eq!(m.rule, "RULE-SET,gh（DOMAIN-SUFFIX,github.com）");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(policy(eval(&engine, Some("www.example.org"), None, 443)), "DIRECT");
        assert_eq!(policy(eval(&engine, None, Some(vec!["1.2.3.4".parse().unwrap()]), 443)), "REJECT");

        let bad = profile(&["DOMAIN,a.com,不存在"]);
        assert!(RuleEngine::compile(&bad, None, None).is_err());
        let bad_cidr = profile(&["IP-CIDR,10.0.0.0/33,DIRECT"]);
        assert!(RuleEngine::compile(&bad_cidr, None, None).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
