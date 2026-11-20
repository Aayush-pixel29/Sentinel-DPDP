// PaisaFlow signup consent (INTENTIONALLY VULNERABLE — Sentinel-DPDP test target)
import { useState } from "react";

export default function SignupConsent({ onSubmit }: { onSubmit: (d: object) => void }) {
  const [phone, setPhone] = useState("");

  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit({ phone }); }}>
      <label htmlFor="phone">Mobile number</label>
      <input id="phone" value={phone} onChange={(e) => setPhone(e.target.value)} />

      {/* VIOLATION 4 (DPDP Sec 6(1)): pre-checked, bundled marketing + data-sharing consent (dark pattern) */}
      <label>
        <input type="checkbox" name="marketing_consent" defaultChecked />
        I agree to the Terms and to share my data with partners for promotional offers
      </label>

      <button type="submit">Create account</button>
    </form>
  );
}
