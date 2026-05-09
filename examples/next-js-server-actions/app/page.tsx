/**
 * Minimal Next.js page that calls the server action.
 */

import { summarise } from "./actions";

export default async function Page() {
  async function go(formData: FormData) {
    "use server";
    const text = String(formData.get("text") ?? "");
    return await summarise(text);
  }

  return (
    <main style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>AGCMS-governed summariser</h1>
      <form action={go}>
        <textarea name="text" rows={6} cols={60} />
        <br />
        <button type="submit">Summarise</button>
      </form>
    </main>
  );
}
