

          +---------------+
          |Config:        |
          |  config_file  |
          |  username     |
          +---------------+
            |          \----------\
            v                     |
    +-----------+                 v
    |Listener:  |+            +-------+             +------------+
    |  socket   ||            |Table: |+            |Backend:    |+
    |  protocol ||--has one-->|  name ||--has many->|  pattern*  ||+
    +-----------+|            +-------+|            |  address   |||
     +-----------+             +-------+            |  port      |||
        ^                                           +------------+||
        |             +-------------+                +------------+|
        |             |Connection:  |+                +------------+
        |             |  state      ||+                  ^
        \-references--|  listener   |||                  |
                      |  client     |||                  |
                      |    socket   |||                  |
                      |    buffer   |||                  |
                      |  server     |||--selected from---/
                      |    socket   |||
                      |    buffer   |||
                      +-------------+||
                       +-------------+|
                        +-------------+

Listeners are listening service ports, each has an associated address, port,
protocol and socket. When an incoming connection is accepted on the
socket, a new connection object is created. The first packet is inspected
and the hostname is extracted from the TLS Client Hello or HTTP Request
(depending on protocol selected). The listener's table is consulted for backend
matching the requested hostname - this match may be simple matching strings or
regular expressions. A second server connection is established to the address
and port specified by the backend, and the initial packet is forwarded to over
this second socket. From this point on, when a packet is received from either
the client or server, its contents are buffered and sent through the other
socket. When either the client or server shuts down its sending side (TCP
half-close), the data buffered from it is flushed to the other socket, whose
sending side is then shut down too, while data keeps being relayed in the
opposite direction. Once both directions have been shut down, or if either
socket fails, the remaining buffered data is sent and both sockets are closed.
After both sockets have been closed the connection is removed.

