# systemd

Linux is still the primary runtime target in this repo.

If you want a long-running node on Linux, `systemd --user` is the intended service model.

Typical flow:

1. create the config with `vx6 init`
2. verify `vx6 node` works manually
3. wrap it in a user service
4. use `vx6 reload` for safe config refresh

The protocol itself is not Linux-only, but the verified IPsec adapter and
privileged service are Linux-only. The ordinary node is a user service; the
IPsec manager is a separate root system service (`vx6-ipsecd`) and requires
strongSwan, the Linux XFRM backend, and nftables. Their install/upgrade
lifecycle is not yet packaged for end users; see [IPsec operations](ipsec.md)
and the [packaging plan](packaging-plan.md).
