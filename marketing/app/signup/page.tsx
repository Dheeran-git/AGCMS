import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Start your trial · AGCMS",
  description:
    "Start a 14-day Starter trial. SSO not required to evaluate. No credit card.",
};

export default function SignupPage() {
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-4xl font-semibold mb-3">Start your free trial</h1>
      <p className="text-fg-muted mb-8">
        14-day Starter trial. No credit card required. Your tenant is provisioned
        with policy packs unselected — pick your frameworks during onboarding.
      </p>

      <form
        method="POST"
        action="/api/signup"
        className="border border-border rounded-lg p-6 bg-panel space-y-4"
      >
        <Field label="Work email" name="email" type="email" required />
        <Field label="Full name" name="name" required />
        <Field label="Company" name="company" required />
        <Field
          label="Subdomain"
          name="subdomain"
          placeholder="acme → acme.agcms.com"
          required
        />

        <label className="flex items-start gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            name="terms"
            required
            className="mt-1 accent-accent"
          />
          <span>
            I agree to the{" "}
            <Link href="/legal/terms" className="text-accent hover:text-accent-bright">
              terms of service
            </Link>{" "}
            and{" "}
            <Link href="/legal/privacy" className="text-accent hover:text-accent-bright">
              privacy policy
            </Link>
            .
          </span>
        </label>

        <button
          type="submit"
          className="bg-accent hover:bg-accent-bright text-white text-sm px-5 py-2.5 rounded-md"
        >
          Create tenant
        </button>
      </form>

      <p className="mt-6 text-sm text-fg-subtle">
        Need SSO, BYOK, or a VPC tier? <Link href="/book-demo" className="text-accent hover:text-accent-bright">Talk to sales →</Link>
      </p>
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
