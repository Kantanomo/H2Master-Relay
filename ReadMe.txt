The Halo 2 Master Server
Live version as of 26th Feb 2017.

Original h2master by Perma Nulled.
Updated and current by Killer Chief /aka/ Glitchy Scripts.

---> Do NOT Distribute! <---

login_details.py contains sensitive login information. 
If you 'need' to send this to someone who is not staff / fully trustworthy, delete that file or null its contents!



server_login.py   is the server that handles player logins and supplying player info to other players in lobbies.

server_relay.py   is the server that relays packets for the in-game LAN (network) server lobby list. Now obsolete, use cache version. However it is useful when migrating the H2Master host and old clients are still on old xlive.dll.

server_relay_cache.py   is the server that relays packets for the in-game LAN (network) server lobby list. It further optimises the relaying of lobby packets by storing a copy of the returned 0x07... packet data indicating an existing lobby. Inside this encoded data is a unique id of sorts specific to the original user that asked if a game exists, so other clients that recieve this don't /usually/ accept this packet. Therefore by swapping this id when relaying it will work for the target client. Among this, this server also adds more commands and also client commands too.

server_sql_relay.py   is a server that can be used for relaying sql queries to the actual database (that the server box that is running this relay can access but the other cannot).



Non Standard Dependencies:
Google protobuf (attached)
pip
pip install pycrypto
pip install requests
MySQL for Python (Find and install it yourself)

Any others?



=== EoF ===