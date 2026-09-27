// SPDX-License-Identifier: Apache-2.0
// Split a byte stream on "\n" only. node:readline also breaks lines at
// U+2028/U+2029 and lone "\r", which JSON.stringify leaves raw inside strings.
export async function* lines(stream) {
  const decoder = new TextDecoder("utf-8");
  let pending = "";
  for await (const chunk of stream) {
    pending += decoder.decode(chunk, { stream: true });
    let i;
    while ((i = pending.indexOf("\n")) !== -1) {
      yield pending.slice(0, i);
      pending = pending.slice(i + 1);
    }
  }
  pending += decoder.decode();
  if (pending) yield pending;
}
