# Test data: fictitious

Every person, patient, address, number and record in this folder is made up for testing the redaction units.
None of it belongs to a real patient or customer. Do not add real documents here, and do not mix real
documents into any corpus built from these files.

| File | What it is |
|---|---|
| `intake-form.pdf` | A five-page fictitious clinic intake form; each page is marked "FICTITIOUS TEST DATA" |
| `intake-form.txt` | The same form as plain text |
| `pii-answer-key.md` | Every planted value (133 items, 109 unique) with its page and type, for scoring |

Where a reserved or published example value exists, the form uses it, so a value that slips through a
redaction is still not someone's real identifier:

| Kind | Values used | Why they are safe |
|---|---|---|
| Phone numbers | `555-0100` to `555-0199` in several area codes | NANPA reserves 555-0100 through 555-0199 for fictional use |
| Email and web addresses | `example.com`, `example.org`, `example.net`, `example-clinic.test` | Reserved for documentation and testing (RFC 2606) |
| IP addresses | `203.0.113.47`, `2001:db8::4a2f:1` | Documentation ranges (RFC 5737, RFC 3849) |
| SSNs | `987-65-4320`, `987-65-4321` | The SSA reserves 987-65-4320 through 987-65-4329 for advertising |
| Card numbers | `4111 1111 1111 1111`, `5555-5555-5555-4444` | Standard card-network test numbers |
| Medicare ID | `1EG4-TE5-MK72` | The example MBI that CMS publishes |
| Bank routing number | `011000015` | A widely published example; it identifies a bank (Federal Reserve Bank of Boston), not a person |

Names, street addresses, MRNs, license and passport numbers, plates and the rest are invented. Some values
are deliberately invalid (for example a card number that fails the Luhn check) to test how the units treat them.
