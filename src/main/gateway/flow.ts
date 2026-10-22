/**
 * Flow identity and the deterministic hash both the NAT and the load balancer key on.
 *
 * A "flow" here is the NAT's unit: one downstream socket, i.e. one (protocol, client address,
 * client port). That is deliberately *not* the 5-tuple: a game or the PS Store opens many
 * connections from one local port to many servers, and a NAT that gives each destination its own
 * mapping is a symmetric NAT, which PSN and party chat punish (NAT type 3). One mapping per client
 * socket — endpoint-independent mapping, what a good home router does — keeps the console at NAT
 * type 2, and still spreads the console's *sockets* across the uplinks, which is what a download
 * manager's speed depends on.
 */

export const PROTO_NAME: Record<number, string> = { 1: 'icmp', 6: 'tcp', 17: 'udp' }

/** The identity of a downstream socket: what a NAT mapping belongs to. */
export interface FlowIdentity {
  /** IANA protocol number: 6 TCP, 17 UDP, 1 ICMP. */
  proto: number
  clientIp: string
  /** For ICMP, the echo identifier stands in for the port. */
  clientPort: number
}

/** A destination seen through a mapping. */
export interface FlowRemote {
  dstIp: string
  dstPort: number
}

export function flowId(flow: FlowIdentity): string {
  return `${flow.proto}:${flow.clientIp}:${flow.clientPort}`
}

export function remoteId(remote: FlowRemote): string {
  return `${remote.dstIp}:${remote.dstPort}`
}

export function protocolName(proto: number): string {
  return PROTO_NAME[proto] ?? String(proto)
}

/**
 * FNV-1a over the given parts. Not cryptographic — it must not be, both for speed and so that a
 * downstream client cannot steer its traffic onto a chosen uplink, which a per-flow hash with a
 * secret salt would only hide. What matters is that it is stable across restarts (so flows keep
 * their uplink after an app restart) and well spread for the parts we feed it.
 */
export function hash32(...parts: (string | number)[]): number {
  let hash = 0x811c9dc5
  for (const part of parts) {
    const text = String(part)
    for (let index = 0; index < text.length; index++) {
      hash ^= text.charCodeAt(index)
      hash = Math.imul(hash, 0x01000193)
    }
    // A separator, so ('ab','c') and ('a','bc') differ.
    hash ^= 0x1f
    hash = Math.imul(hash, 0x01000193)
  }
  return hash >>> 0
}

/** A hash value mapped to (0, 1), exclusive, as the rendezvous hashing below needs. */
export function unitInterval(...parts: (string | number)[]): number {
  // +1 and /2^32 keep it off both ends: log(0) is -Infinity and would win every comparison.
  return (hash32(...parts) + 1) / 4294967297
}
