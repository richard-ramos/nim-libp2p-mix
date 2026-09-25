# SPDX-License-Identifier: Apache-2.0 OR MIT
{.used.}
import chronos, results, metrics
import libp2p/switch
import libp2p/stream/connection
import libp2p_mix
import
  libp2p_mix/[mix_protocol, spam_protection, cover_traffic, mix_metrics, delay_strategy]
import ../utils
import ../tools/[unittest, lifecycle, crypto]

type AsyncProofs = ref object of SpamProtection
  generated, verified: int
  unavailable, blocked, pending, cancelled: bool

method precomputeCoverProofs(sp: AsyncProofs): bool {.gcsafe, raises: [].} =
  false

method generateProofAsync(
    sp: AsyncProofs, packet: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  if sp.blocked:
    sp.pending = true
    try:
      await sleepAsync(1.minutes)
    except CancelledError as exc:
      sp.cancelled = true
      raise exc
    finally:
      sp.pending = false
  await sleepAsync(5.milliseconds)
  if sp.unavailable:
    return err("backend unavailable")
  inc sp.generated
  return ok(ProofResult(proof: @[packet[0]]))

method verifyProofAsync(
    sp: AsyncProofs, proof, packet: seq[byte]
): Future[Result[bool, string]] {.async: (raises: [CancelledError]).} =
  await sleepAsync(5.milliseconds)
  inc sp.verified
  return ok(proof == @[packet[0]])

suite "Asynchronous proof provider":
  asyncTest "cover precomputation spends no proofs; routing awaits per-hop proofs":
    let infos = MixNodeInfo.generateRandomMany(5, rng())
    var nodes: seq[MixProtocol]
    var providers: seq[AsyncProofs]
    for info in infos:
      let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
      let provider = AsyncProofs(proofSize: 1)
      let node = MixProtocol.new(
        info,
        sw,
        spamProtection = Opt.some(SpamProtection(provider)),
        delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      )
      for other in infos:
        if other.peerId != info.peerId:
          node.nodePool.add(other.toMixPubInfo())
      sw.mount(node)
      nodes.add(node)
      providers.add(provider)
    startAndDeferStop(nodes)
    let received = mix_cover_received.value()
    let cover = (await nodes[0].buildCoverPacket()).tryGet()
    check providers[0].generated == 0
    check cover.proofToken.len == 0
    check (
      await nodes[0].sendCoverPacket(
        cover.firstHopPeerId, cover.firstHopAddr, cover.packet
      )
    ).isOk
    checkUntilTimeout:
      mix_cover_received.value() > received
    var generated, verified: int
    for sp in providers:
      generated += sp.generated
      verified += sp.verified
    check generated == 3
    check verified == 3
    providers[0].unavailable = true
    let next = (await nodes[0].buildCoverPacket()).tryGet()
    check (
      await nodes[0].sendCoverPacket(
        next.firstHopPeerId, next.firstHopAddr, next.packet
      )
    ).isErr
    check providers[0].generated == 1

    providers[0].unavailable = false
    providers[0].blocked = true
    let conn = nodes[0]
      .toConnection(MixDestination.exitNode(infos[4].peerId), "/mix/test/cancel/1.0.0")
      .tryGet()
    defer:
      await conn.close()
    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      providers[0].pending
    await sending.cancelAndWait()
    check providers[0].cancelled
    check not providers[0].pending
