export default function BookDemoPage() {
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-4xl font-semibold mb-3">Book a 30-minute demo</h1>
      <p className="text-fg-muted mb-8">
        We'll walk through SSO onboarding, governed traffic, the live audit
        chain, and the public verifier. Bring a real-world test prompt — we'll
        run it.
      </p>

      <form
        method="POST"
        action="/api/book-demo"
        className="border border-border rounded-lg p-6 bg-panel space-y-4"
      >
        <Field label="Work email" name="email" type="email" required />
        <Field label="Company" name="company" required />
        <Field label="Role" name="role" placeholder="e.g. Chief Compliance Officer" />
        <Field label="Compliance frameworks (comma-separated)" name="frameworks" />
        <button
          type="submit"
          className="bg-accent hover:bg-accent-bright text-white text-sm px-5 py-2.5 rounded-md"
        >
          Request a slot
        </button>
      </form>
    </div>
  );
}

function Field(props: {
  label: string;
  name: string;
  type?: string;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="block text-sm text-fg-muted mb-1">{props.label}</span>
      <input
        name={props.name}
        type={props.type ?? "text"}
        required={props.required}
        placeholder={props.placeholder}
        className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-fg-primary focus:border-accent outline-none"
      />
    </label>
  );
}
