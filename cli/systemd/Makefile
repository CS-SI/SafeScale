.PHONY:	install

CP?=cp

install:
	@($(CP) -f ../safescale/safescale /usr/local/bin/ || true)
	@($(CP) -f ../safescaled/safescaled /usr/local/bin/ || true)
	@($(CP) -f ../systemd/safescale.service /lib/systemd/system/ || true)
	@($(CP) -f ../systemd/safescale.socket /lib/systemd/system/ || true)

	@(mkdir -p /etc/safescale || true)
	@(touch /etc/safescale/tenants.toml || true)
	@(systemctl enable safescale.service || true)