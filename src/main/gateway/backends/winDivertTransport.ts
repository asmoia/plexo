/**
 * How the capture process talks to the app.
 *
 * There are two ways a Node process can be given a message channel, and this code got it wrong once:
 * the capture process was written for Electron's `utilityProcess` (`process.parentPort`) but is
 * spawned with `child_process` (`process.send`). The mismatch is invisible in review and fatal in
 * use — `process.parentPort` is `undefined`, the first `postMessage` throws, and the process exits
 * with code 1 before it can say why. The app then blames the driver, and the driver is fine.
 *
 * So the choice is made here, explicitly, from whatever the process actually has, and it is a pure
 * function of that: testable with fakes, and impossible to get silently wrong.
 */

export interface CaptureTransport {
  send: (message: unknown) => void
  receive: (listener: (message: unknown) => void) => void
}

/**
 * The parts of a process's IPC surface this cares about. Deliberately loose: Node's `process` and
 * Electron's `parentPort` have their own (overloaded) signatures, and all that matters here is that
 * messages go out and come in.
 */
export interface TransportSource {
  /** Electron's `utilityProcess` channel. */
  parentPort?: {
    postMessage: (message: never) => void
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    on: (event: any, listener: any) => void
  }
  /** `child_process`'s channel: `process.send` plus `process.on('message')`. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  send?: (message: any, ...rest: any[]) => unknown
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on?: (event: any, listener: any) => unknown
}

/**
 * The channel this process was given. Throws with a sentence a person can act on when there is
 * none — a capture process with no channel cannot deliver a single packet, so failing is the honest
 * outcome.
 */
export function openTransport(source: TransportSource): CaptureTransport {
  if (source.parentPort) {
    const port = source.parentPort
    return {
      send: (message) => port.postMessage(message as never),
      receive: (listener) => port.on('message', (event: { data: unknown }) => listener(event.data))
    }
  }
  if (typeof source.send === 'function' && typeof source.on === 'function') {
    const send = source.send.bind(source)
    const on = source.on.bind(source)
    return {
      send: (message) => send(message),
      receive: (listener) => on('message', (message) => listener(message))
    }
  }
  throw new Error(
    'the capture process was started without an IPC channel, so it cannot pass packets to Plexo'
  )
}
