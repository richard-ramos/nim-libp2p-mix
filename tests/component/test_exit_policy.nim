# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Logos

{.used.}

import chronos, results
import std/sequtils
import libp2p/[builders, switch, multiaddress, peerid]
import libp2p/crypto/[crypto, secp]
import libp2p/protocols/protocol
import libp2p/stream/connection
import libp2p_mix
import libp2p_mix/[mix_protocol, cover_traffic]
import ../tools/unittest

type
  Counter = ref object
    received: int

  CoverCounter = ref object of CoverTraffic
    received: int

method start(ct: CoverCounter) {.async: (raises: [CancelledError]).} =
  discard

method stop(ct: CoverCounter) {.async: (raises: []).} =
  discard

method onCoverReceived(ct: CoverCounter) {.gcsafe, raises: [].} =
  inc ct.received

proc makeSwitch(info: MixNodeInfo, rng: Rng): Switch =
  SwitchBuilder
    .new()
    .withRng(rng)
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: info.libp2pPrivKey))
    .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").tryGet())
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

proc receiver(counter: Counter): LPProtocol =
  LPProtocol.new(
    codecs = @["/mix/test/roles/1.0.0"],
    handler = proc(
        conn: Connection, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        let payload = await conn.readLp(1024)
        doAssert payload == @[1.byte, 2, 3]
        inc counter.received
      except LPStreamError:
        discard
      finally:
        await conn.close()
    ,
  )

proc send(proto: MixProtocol, dest: MixDestination): Future[bool] {.async.} =
  let conn = proto.toConnection(dest, "/mix/test/roles/1.0.0").tryGet()
  defer:
    await conn.close()
  try:
    await conn.writeLp(@[1.byte, 2, 3])
    return true
  except LPStreamError:
    return false

proc exitPolicy(allowExit: bool) {.async.} =
  let rng = newRng()
  var infos = MixNodeInfo.generateRandomMany(5, rng)
  var switches: seq[Switch]
  var protos: seq[MixProtocol]
  let cover = CoverCounter(slotPool: SlotPool.new(100))
  let local = Counter()
  let external = Counter()
  for i in 0 ..< infos.len:
    let sw = makeSwitch(infos[i], rng)
    let ct =
      if i == 4:
        Opt.some(CoverTraffic(cover))
      else:
        Opt.none(CoverTraffic)
    let proto =
      MixProtocol.new(infos[i], sw, allowExit = i == 4 and allowExit, coverTraffic = ct)
    sw.mount(proto)
    if i == 4:
      sw.mount(receiver(local))
    switches.add(sw)
    protos.add(proto)
  defer:
    await switches.mapIt(it.stop()).allFutures()
  let dest = makeSwitch(MixNodeInfo.generateRandom(0, rng), rng)
  dest.mount(receiver(external))
  defer:
    await dest.stop()
  await switches.mapIt(it.start()).allFutures()
  await dest.start()
  for i in 0 ..< infos.len:
    infos[i].multiAddr = switches[i].peerInfo.addrs[0]
    protos[i].setLocalMultiAddr(infos[i].multiAddr).expect("bound address")
  for i in 0 ..< infos.len:
    for j in 0 ..< infos.len:
      if i == j:
        continue
      var info = infos[j].toMixPubInfo()
      info.exitEnabled = j == 4 and allowExit
      protos[i].nodePool.add(info)

  let localDest = MixDestination.exitNode(infos[4].peerId)
  let externalDest =
    MixDestination.forwardToAddr(dest.peerInfo.peerId, dest.peerInfo.addrs[0])
  if not allowExit:
    doAssert not await send(protos[0], localDest)
    doAssert not await send(protos[0], externalDest)
    # A stale or forged advertisement must not bypass the receiving node's policy.
    var advertised = infos[4].toMixPubInfo()
    advertised.exitEnabled = true
    protos[0].nodePool.add(advertised)

  doAssert await send(protos[0], localDest)
  doAssert await send(protos[0], externalDest)
  for attempt in 0 ..< 100:
    if allowExit and local.received == 1 and external.received == 1:
      break
    await sleepAsync(20.milliseconds)
  doAssert local.received == (if allowExit: 1 else: 0)
  doAssert external.received == (if allowExit: 1 else: 0)

  # Every other node is intermediate-only, and the loop endpoint may be too.
  let packet = protos[4].buildCoverPacket().expect("build cover loop")
  (
    await protos[4].sendCoverPacket(
      packet.firstHopPeerId, packet.firstHopAddr, packet.packet
    )
  ).expect("send cover loop")
  for attempt in 0 ..< 100:
    if cover.received == 1:
      break
    await sleepAsync(20.milliseconds)
  doAssert cover.received == 1
  echo "PASS: exit policy allowExit=", allowExit, "; cover loop received"

suite "Exit role policy":
  asyncTest "intermediates reject application exits but consume cover loops":
    await exitPolicy(false)
  asyncTest "opted-in exits deliver locally and externally":
    await exitPolicy(true)
