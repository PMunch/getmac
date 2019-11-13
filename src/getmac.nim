import options, os, osproc, strutils, net
import optionsutils

type
  MacAddr* = distinct string

proc `$`*(x: MacAddr): string {.borrow.}

proc checkArpFile(ip: string): Option[string] =
  if fileExists("/proc/net/arp"):
    for line in "/proc/net/arp".lines:
      var columns = line.splitWhitespace()
      if columns.len >= 4 and columns[0] == ip:
        return some(columns[3])

proc checkIpNeighShow(ip: string): Option[string] =
  let res = execProcess("ip neighbour show " & ip)
  if res.startsWith(ip):
    let columns = res.splitWhitespace()
    if columns.len >= 5 and columns[3] == "lladdr":
      return some(res.splitWhitespace()[4])

proc checkArp(ip: string): Option[string] =
  when hostOs == "windows":
    let res = execProcess("arp.exe -a " & ip)
    for line in res.splitLines:
      let columns = line.splitWhitespace()
      if columns.len >= 2 and columns[0] == ip:
        return some(columns[1].replace('-', ':'))
  else:
    let res = execProcess("arp -en " & ip)
    var first = true
    for line in res.splitLines:
      let columns = line.splitWhitespace()
      if not first and columns.len >= 3 and columns[0] == ip:
        return some(columns[2])
      first = false

proc verifyMac*(mac: string): Option[MacAddr] =
  ## Takes a string and verifies if it is a valid MAC address or not. Will
  ## return a distinct ``MacAddr`` string if it is valid.
  if mac.count(':') != 5: return none(MacAddr)
  var onlynils = true
  for i, c in mac:
    if (i + 1) mod 3 == 0:
      if c != ':': return none(MacAddr)
    elif c notin HexDigits: return none(MacAddr)
    if c notin {':', '0'}: onlynils = false
  if not onlynils:
    return some(mac.MacAddr)

const PingPort = some(Port(55555))

proc getmac*(ip: string, ping = none(Port), pingDelay = 1): Option[MacAddr] =
  ## This procedure takes an IP address and polls the machine ARP cache in a
  ## platform independent way. If a ``Port`` is supplied to ``ping`` it will
  ## first send an empty UDP package to that port in order to populate the
  ## cache. However since this might take a short while to propagate you can
  ## also supply a ``pingDelay`` in milliseconds that will simply be awaited
  ## between the package is sent and the cache is queried. If you expect high
  ## delays it might be better to do run this once with a ``ping`` and then
  ## later run it in a loop without it to poll for an entry. The ARP cache only
  ## does local devices, so querying the MAC address of a non-local IP address
  ## will not yield any results.
  withSome ping:
    some port:
      var socket = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
      socket.sendTo(ip, port, "")
      socket.close()
      sleep(pingDelay)
    none: discard
  (when hostOS == "windows":
    checkArp(ip)
  else:
    optOr(checkArpFile(ip), checkIpNeighShow(ip), checkArp(ip))
  )?.verifyMac

proc toBytes*(mac: MacAddr): array[6, byte] =
  ## Converts a MAC address string to an array of bytes.
  var hexstr = mac.string.split(':')
  assert(hexstr.len == 6, "Invalid MAC address!")
  for i, b in hexstr:
    result[i] = parseHexInt(b).byte

when isMainModule:
  echo "Without ping:\t", getmac(paramStr(1))
  echo "With ping:\t", getmac(paramStr(1), PingPort)
