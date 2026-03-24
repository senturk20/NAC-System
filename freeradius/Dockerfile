# ============================================================
# FreeRADIUS - Custom Dockerfile
# ============================================================
# WHY: Bind-mounting config files from Windows gives them 0777
# permissions. FreeRADIUS refuses to start if configs are
# "globally writable" (security check). By COPYing files
# inside the image, we control the exact permissions.
# ============================================================

FROM freeradius/freeradius-server:latest-3.2

# Copy our custom config files into the container
COPY clients.conf /etc/freeradius/clients.conf

# Copy the rest module config (tells FreeRADIUS to call our API)
COPY mods-enabled/rest /etc/freeradius/mods-enabled/rest

# Copy our simplified default site (wires rest into authorize/authenticate/accounting)
COPY sites-enabled/default /etc/freeradius/sites-enabled/default

# Fix ownership and permissions so FreeRADIUS accepts them:
#   - freerad:freerad is the user/group that radiusd runs as
#   - 640 = owner read+write, group read, others nothing
RUN chown -R freerad:freerad /etc/freeradius/ \
    && chmod -R 640 /etc/freeradius/clients.conf \
                     /etc/freeradius/mods-enabled/rest \
                     /etc/freeradius/sites-enabled/default
