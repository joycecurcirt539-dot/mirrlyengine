use mirrlyengine::balancer::BALANCER;
use mirrlyengine::cfproxy::{cache_resolved_ips_if_current, cached_resolved_ips};
use mirrlyengine::config::CFPROXY;
use mirrlyengine::generation_guard::{apply_if_current, change_config, snapshot};
use mirrlyengine::network_profile::{apply_profile, get_profile};
use mirrlyengine::recovery::{record_if_current, RecoveryCause};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Notify;

fn apply_ranked_if_current(
    expected: mirrlyengine::generation_guard::GenerationStamp,
    dc: i32,
    ranked: Vec<(String, u64)>,
) -> bool {
    apply_if_current(expected, || {
        BALANCER
            .write()
            .update_ranked_domains_for_dc(dc, false, ranked);
    })
    .is_some()
}

#[tokio::test]
async fn slow_result_a_cannot_rewrite_or_reset_generation_b() {
    const DC: i32 = 203;
    const B: &str = "mob020-worker-b.example";
    const DNS_HOST: &str = "mob020-dns.example";

    let a = snapshot();
    let release_a = Arc::new(Notify::new());
    let waiting = release_a.clone();
    let late_a = tokio::spawn(async move {
        waiting.notified().await;
        let old_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let rank_applied = apply_ranked_if_current(
            a,
            DC,
            vec![("mob020-worker-a.example".to_string(), 1)],
        );
        let dns_applied = cache_resolved_ips_if_current(a, DNS_HOST, vec![old_ip]);
        let recovery_applied =
            record_if_current(a, "mob020-worker-a.example", RecoveryCause::Unknown);
        (rank_applied, dns_applied, recovery_applied.is_some())
    });

    let mut profile_b = get_profile();
    profile_b.generation += 1;
    profile_b.validated = true;
    profile_b.suspended = false;
    apply_profile(profile_b);
    change_config(|| {
        CFPROXY.write().user_domain = B.to_string();
        BALANCER.write().update_domain_for_dc(DC, false, B);
    });
    let b = snapshot();
    let b_ip: IpAddr = "192.0.2.20".parse().unwrap();
    assert!(cache_resolved_ips_if_current(b, DNS_HOST, vec![b_ip]));

    release_a.notify_one();
    let (rank_applied, dns_applied, recovery_applied) = late_a.await.unwrap();
    assert!(!rank_applied, "A overwrote B's active race winner");
    assert!(!dns_applied, "A overwrote B's DNS cache");
    assert!(!recovery_applied, "A initiated recovery/reset in B");
    assert_eq!(
        BALANCER.read().get_active_domain_for_dc(DC, false).as_deref(),
        Some(B)
    );
    assert_eq!(cached_resolved_ips(DNS_HOST), Some(vec![b_ip]));
    assert_eq!(snapshot(), b, "stale A changed B's generation");

    let mut same_network_new_profile = get_profile();
    same_network_new_profile.screen_on = !same_network_new_profile.screen_on;
    apply_profile(same_network_new_profile);
    assert_eq!(snapshot().network, b.network);
    assert_ne!(snapshot().profile, b.profile);
    assert!(!apply_ranked_if_current(
        b,
        DC,
        vec![("mob020-old-profile.example".to_string(), 1)],
    ));
    assert_eq!(
        BALANCER.read().get_active_domain_for_dc(DC, false).as_deref(),
        Some(B)
    );
}
