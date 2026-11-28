# What redact treats as PII

This is the written definition every layer of the redaction unit follows: the rules, the classifier's labels, the LLM's type list and the answer keys used to score it. The machine copy is [`unit/pii/taxonomy.json`](../unit/pii/taxonomy.json), and the two list the same classes.

## Edge calls

These are the edge calls this definition makes. Each one is a default, and a client profile can change the Tier B ones.

1. **Every date more specific than a year is redacted**, dates of service included. HIPAA Safe Harbor removes all elements of dates except the year, and recall comes first.
2. **Nicknames are names** (Tier A `PERSON`), not a separate Tier B class, so "Ellie" and "Tom" can never be switched off.
3. **One organization class.** Employers, pharmacies, clinics, carriers and banks named in a document about a person are all `ORGANIZATION` (Tier B). That redacts the clinic's own name in its letterhead too. A profile can allow-list a name that is fine to keep.
4. **Health content stays** under `strict`: diagnoses, codes, medications, allergies, procedures and blood type. Safe Harbor keeps clinical content, and a cleaned intake form is useless without it. `HEALTH_INFO` exists so a profile can turn it on.
5. **Labels stay, values go.** `SSN: 987-65-4320` becomes `SSN: [SSN_1]`. A value spelled exactly like a label word (a city called Mobile next to a phone number) can slip past the classifier and the LLM; the rules still see it when it has a label of its own.
6. **Partial values count.** "Card ending in 1111" and "account ending 6789" are redacted, and an output that keeps any name token, a house number with its street, or a run of four or more digits from a value counts as a leak of that value.
7. **Order numbers, dollar amounts, page numbers and a year on its own are kept.**
8. **A secret is redacted wherever it sits, code and config included.** API keys, tokens, private keys, passwords and seed phrases are Tier A even in a document that is not about a person, because a leaked key does harm on its own. Redacting one from a copy does not make it safe: a key or seed phrase that was ever in the original should be rotated or moved.

## Tiers

| Tier | Meaning | Under `strict` |
|---|---|---|
| A | Direct identifiers | Always redacted; no profile can turn one off |
| B | Identifying in context (city, age, occupation, employer) | Redacted; a profile may turn one off |
| C | Combinations of quasi-identifiers | Documented below; no detector, nothing promised |
| H | Health content | Kept; a profile may turn it on |

Tier C, documented and not detected:

- Rare combinations of Tier B values (for example a small town, an exact age over 89 and an occupation) that single out a person even with every listed class redacted.
- Free-text events that only one person matches (for example 'the only cardiologist in town who fell off the ferry last June').
- Family structure combined with ages (for example 'two children, ages 12 and 9') once names are gone.

## Sources

- HIPAA Safe Harbor de-identification, 45 CFR 164.514(b)(2): the 18 identifier types, including all elements of dates except the year and any other unique identifying number, characteristic or code.
- NIST SP 800-122, Guide to Protecting the Confidentiality of Personally Identifiable Information: linked and linkable information, which is where Tier B comes from.
- GDPR Article 4(1) (personal data) and Article 9 (special categories, including health data).
- California Civil Code 1798.140 (CCPA definition of personal information).

## How the layers use this

- **Rules** redact formats distinctive enough to stand alone (emails, URLs, IPs, phone numbers with separators, valid dashed SSNs, Luhn-valid card numbers, Medicare MBIs, VINs with a valid check digit, dates, API keys and tokens with a published prefix, private key blocks, seed phrases). Every other number needs one of the class's labels just before it, and is then redacted even when its checksum fails. Secrets also count as the value of a setting whose name says it holds one, the field after a password label, or a table cell under a secret heading; see `CREDENTIAL`, `SECRET` and `SEED_PHRASE`.
- **The classifier** (GLiNER-PII) is asked for each active class's `classifier labels`.
- **The LLM** sees what the first two layers left and types each remaining run of capitalized words as one of the classes marked `llm` below, or as not personal. Numbers are left to the rules and the classifier.
- A span made only of label words (the taxonomy's `form_words`), common words and titles is treated as a label and kept.

## Classes

### `PERSON`

Person name. Tier A, placeholder `[PERSON_n]`, caught by rules, classifier, llm.

Any name of a person: full, first, middle, last, nickname or preferred name, initials with a surname, and names in signatures. Patients, relatives, contacts, staff and clinicians alike.

- Examples: `Eleanor Marguerite Whitfield`; `Ellie`; `Dr. Patel`; `/s/ Hope Stone`
- Not this class: the word hope in 'we hope you feel better'; a drug or product named after a person
- Labels the rules look for: `name`, `patient`, `subscriber`, `account holder`, `spouse`, `child \d*`, `mother`, `father`, `contact`, `signature`, `witness`
- Classifier labels: `name`, `first name`, `last name`, `name medical professional`

### `SSN`

Social Security number. Tier A, placeholder `[SSN_n]`, caught by rules, classifier.

A US Social Security number in any format, including partial ones (last four digits) and ones written out in words.

- Examples: `987-65-4320`; `nine eight seven, sixty-five, four three two zero`; `SSN ending 4320`
- Not this class: a nine-digit order or part number with no SSN label
- Labels the rules look for: `ssn`, `social security(?: number| no\.?)?`, `ss#`, `soc\.? sec\.?`
- Classifier labels: `ssn`

### `ITIN`

Taxpayer identification number. Tier A, placeholder `[ITIN_n]`, caught by rules.

An ITIN, EIN or other taxpayer number issued to a person.

- Examples: `912-70-1234`
- Not this class: a company EIN printed in a letterhead
- Labels the rules look for: `itin`, `tin`, `taxpayer id(?:entification)?(?: number| no\.?)?`, `tax id`

### `DATE`

Date linked to a person. Tier A, placeholder `[DATE_n]`, caught by rules, classifier.

Every date more specific than a year in a document about a person: birth, death, visit, admission, payment, signature and expiry dates. A year on its own is kept (HIPAA Safe Harbor allows it).

- Examples: `03/14/1979`; `14-Mar-1979`; `June 3rd, 2026`; `the 12th of September`; `Jan. 2018`
- Not this class: 2019 on its own; a form revision year
- Labels the rules look for: `date`, `dob`, `born`, `deceased`, `expires?`, `exp\.?`
- Classifier labels: `dob`, `date`

### `PHONE`

Phone number. Tier A, placeholder `[PHONE_n]`, caught by rules, classifier.

Any telephone number, with or without country code or extension.

- Examples: `(312) 555-0142`; `+1 312 555 0119 x204`
- Not this class: a ten-digit NPI or account number with its own label
- Labels the rules look for: `phone`, `tel\.?`, `telephone`, `mobile`, `cell`, `home`, `work`, `line`
- Classifier labels: `phone number`

### `FAX`

Fax number. Tier A, placeholder `[FAX_n]`, caught by rules.

A fax number.

- Examples: `(847) 555-0199`
- Labels the rules look for: `fax`

### `EMAIL`

Email address. Tier A, placeholder `[EMAIL_n]`, caught by rules, classifier.

Any email address, including shared or role mailboxes that appear in the document.

- Examples: `ellie.whitfield@example.com`; `records@example-clinic.test`
- Labels the rules look for: `e-?mail`
- Classifier labels: `email address`

### `STREET_ADDRESS`

Street address. Tier A, placeholder `[ADDRESS_n]`, caught by classifier, llm.

A street address: house number, street, unit, PO box. Current, prior and billing addresses alike.

- Examples: `1427 Maplewood Lane, Apt 3B`; `5520 Orange Grove Avenue`
- Not this class: a street name used as a direction with no number, such as 'take Davis Street north'
- Labels the rules look for: `address`, `addr\.?`, `street`, `lived at`
- Classifier labels: `location address`, `location street`

### `MRN`

Medical record number. Tier A, placeholder `[MRN_n]`, caught by rules.

A medical record, chart or patient account number at a care provider.

- Examples: `MRN-00482913`
- Labels the rules look for: `mrn`, `medical record(?: no\.?| number| #)?(?: \(mrn\))?`, `chart(?: no\.?| number| #)`

### `HEALTH_PLAN_ID`

Health plan or member ID. Tier A, placeholder `[MEMBER_ID_n]`, caught by rules, classifier.

A health plan beneficiary, member, subscriber, policy or group number.

- Examples: `XMH884213907`; `GRP-0057731`; `SDV-55102-88`
- Not this class: a plan name such as 'PPO Gold'
- Labels the rules look for: `member(?: id| no\.?| number| #)`, `subscriber(?: id| no\.?| number)`, `group(?: no\.?| number| #)`, `policy(?: id| no\.?| number| #)?`, `plan id`, `insurance id`, `beneficiary(?: id| number)`

### `MEDICARE_ID`

Medicare beneficiary identifier. Tier A, placeholder `[MBI_n]`, caught by rules.

A Medicare Beneficiary Identifier (11 characters in the CMS format) or an older Medicare claim number.

- Examples: `1EG4-TE5-MK72`
- Labels the rules look for: `mbi`, `medicare(?: beneficiary)?(?: id| identifier| number| no\.?)?(?: \(mbi\))?`

### `ACCOUNT_NUMBER`

Account number. Tier A, placeholder `[ACCOUNT_n]`, caught by rules, classifier.

A bank, billing or other financial account number, including the last four digits on their own.

- Examples: `000123456789`; `account ending 6789`
- Not this class: a dollar amount
- Labels the rules look for: `account(?: no\.?| number| #)?`, `acct\.?(?: no\.?| #)?`, `account ending(?: in)?`
- Classifier labels: `account number`, `bank account`

### `CARD_NUMBER`

Payment card number. Tier A, placeholder `[CARD_n]`, caught by rules, classifier.

A credit or debit card number, whether or not its checksum is valid, including the last four digits on their own.

- Examples: `4111 1111 1111 1111`; `card ending in 1111`
- Labels the rules look for: `card(?: number| no\.?| #)?`, `number`, `card ending(?: in)?`, `visa`, `mastercard`, `amex`, `american express`, `discover`
- Classifier labels: `credit card`

### `CARD_EXPIRY`

Card expiry date. Tier A, placeholder `[CARD_EXP_n]`, caught by rules, classifier.

The expiry date of a payment card.

- Examples: `09/28`; `12/2027`
- Labels the rules look for: `exp\.?`, `expiry`, `expiration(?: date)?`, `expires`, `valid thru`, `good thru`
- Classifier labels: `credit card expiration`

### `CARD_CVV`

Card security code. Tier A, placeholder `[CVV_n]`, caught by rules, classifier.

A card verification code (CVV, CVC, CID).

- Examples: `737`
- Labels the rules look for: `cvv2?`, `cvc2?`, `cid`, `security code`
- Classifier labels: `cvv`

### `ROUTING_NUMBER`

Bank routing number. Tier A, placeholder `[ROUTING_n]`, caught by rules, classifier.

An ABA routing transit number. It names a bank, not a person, but it is redacted with the account it belongs to.

- Examples: `011000015`
- Not this class: a bare nine-digit number with no routing label
- Labels the rules look for: `routing(?: no\.?| number| #)?`, `aba(?: no\.?| number| #)?`, `rtn`
- Classifier labels: `routing number`

### `DRIVERS_LICENSE`

Driver's license number. Tier A, placeholder `[DL_n]`, caught by rules, classifier.

A driver's license or state ID number, with its state prefix when one is written.

- Examples: `IL D400-7821-9935`
- Labels the rules look for: `driver'?s? licen[sc]e(?: no\.?| number| #)?`, `dl(?: no\.?| #)?`, `state id(?: no\.?| number)?`
- Classifier labels: `driver license`

### `PASSPORT`

Passport number. Tier A, placeholder `[PASSPORT_n]`, caught by rules, classifier.

A passport number.

- Examples: `X12345678`
- Labels the rules look for: `passport(?: no\.?| number| #)?`
- Classifier labels: `passport number`

### `VIN`

Vehicle identification number. Tier A, placeholder `[VIN_n]`, caught by rules.

A 17-character vehicle identification number.

- Examples: `1M8GDM9AXKP042788`
- Labels the rules look for: `vin`

### `LICENSE_PLATE`

License plate. Tier A, placeholder `[PLATE_n]`, caught by rules.

A vehicle license plate number.

- Examples: `BQ 48213`
- Not this class: a vehicle make, model or year
- Labels the rules look for: `plate(?: no\.?| number| #)?`, `license plate`, `tag(?: no\.?| number)`

### `IP_ADDRESS`

IP address. Tier A, placeholder `[IP_n]`, caught by rules, classifier.

An IPv4 or IPv6 address.

- Examples: `203.0.113.47`; `2001:db8::4a2f:1`
- Not this class: a version string such as version 1.2.3.4
- Labels the rules look for: `ip`, `ipv[46]`, `address`
- Classifier labels: `ip address`

### `MAC_ADDRESS`

Device identifier. Tier A, placeholder `[MAC_n]`, caught by rules.

A MAC address, device serial number or other device identifier.

- Examples: `00:1A:2B:3C:4D:5E`
- Labels the rules look for: `mac(?: address)?`, `serial(?: no\.?| number| #)?`, `device id`

### `URL`

Web address. Tier A, placeholder `[URL_n]`, caught by rules, classifier.

Any URL in the document. Portal and profile links often carry a user name.

- Examples: `https://portal.example-clinic.test/patients/ewhitfield79`
- Labels the rules look for: `url`, `portal`, `website`, `link`
- Classifier labels: `url`

### `CREDENTIAL`

Credential. Tier A, placeholder `[CREDENTIAL_n]`, caught by rules, classifier.

A user name, password, passphrase, PIN or security answer, and the user:password part of a connection string. After a field label the whole value is taken, letters-only and multi-word values included; after any other label it needs a digit or a symbol.

- Examples: `username ewhitfield79`; `Guest Wi-Fi password: sunshine`; `Backup passphrase: correct horse battery staple`; `postgres://admin:<password>@db.example.com/app`
- Not this class: the word password in a sentence such as 'reset your password at the front desk'; a blank field: 'Password: ________'
- Labels the rules look for: `user(?: ?name)?`, `login`, `password`, `passcode`, `pass ?phrase`, `passwd`, `pwd`, `pin(?: code| number)?`, `api key`, `token`, `security (?:question )?answer`, `secret answer`, `memorable (?:word|phrase)`, `wi-?fi key`, `network key`
- Field labels (the value after `:`, `=` or a table cell is taken as written): `password`, `passcode`, `pass ?phrase`, `passwd`, `pwd`, `(?-i:PIN)(?: code| number)?` (PIN in capitals, so a `Pin` column of version pins is not read as passwords), `security (?:question )?answer`, `secret answer`, `memorable (?:word|phrase)`, `wi-?fi key`, `network key`; and a bare `Answer:` within 200 characters after a security question
- Classifier labels: `username`, `password`

### `SECRET`

API key, token or private key. Tier A, placeholder `[SECRET_n]`, caught by rules.

A value that grants access on its own: an API key, access or bearer token, client or signing secret, session token (JWT), private key block (PEM, OpenSSH, PGP, PuTTY), crypto wallet private key, or disk recovery key. Caught by its published prefix or shape, after a key, token or secret label, as the value of a setting whose name says it holds one (OPENAI_API_KEY=..., "client_secret": "..."), in an Authorization header, or in a table column headed by one of these labels.

- Examples: `ghp_` and 36 letters and digits (GitHub); `AKIA` and 16 capitals and digits (AWS); a whole private key block, from its BEGIN OPENSSH PRIVATE KEY line to its END line; `OPENAI_API_KEY=<value>`; `Authorization: Bearer <value>`
- Not this class: a public key or its fingerprint; a client ID; a hash or checksum with no key or token label; a reference to a secret, such as `${API_KEY}` or `process.env.API_KEY`
- Labels the rules look for: `api[ _-]?(?:key|secret|token)`, `access[ _-]?(?:key|token)(?: id)?`, `secret(?: access)?(?: key)?`, `client[ _-]?secret`, `auth(?:entication|orization)?[ _-]?(?:key|token)`, `bearer`, `(?:refresh|session|personal access|deploy|bot|webhook) token`, `token`, `private[ _-]?key`, `signing[ _-]?(?:key|secret)`, `webhook[ _-]?secret`, `recovery key`, `license key`

Known formats, redacted with no label: GitHub, GitLab, Slack, Stripe, Anthropic, OpenAI, Google (API key, OAuth secret and access token), AWS access key IDs, Hugging Face, npm, PyPI, SendGrid, Twilio, Shopify, DigitalOcean, Docker Hub, Grafana, Linear, xAI, Groq, Notion, Mailgun and Square tokens, Telegram bot tokens, JWTs, BitLocker recovery keys, BIP-32 extended private keys, and WIF private keys that pass their base58check checksum. After a label the value must be 16 or more characters with a digit, 24 or more without one, or `0x` and 64 hex digits.

A setting counts when its name holds a secret word (`secret`, `token`, `apikey`, `credential`, or `key` with a qualifier such as `api`, `access` or `private`) and no word that marks it as something else (`url`, `id`, `name`, `public`, `type`, `length` and similar). A name in capitals (`JWT_SECRET=...`) is trusted with any value; other names need a value with a digit, or 20 or more characters, so that code (`token = next_token()`), references (`${API_KEY}`) and placeholders (`your-api-key`) are left alone. A bare `Token` or `Bearer` column heading does not count, since design tokens and coins use it too, and a cell that is an environment variable name (`OPENAI_API_KEY`) is a name, not a value.

### `SEED_PHRASE`

Wallet seed phrase. Tier A, placeholder `[SEED_PHRASE_n]`, caught by rules.

A crypto wallet recovery phrase, which gives whoever reads it control of the wallet: 12 or more words in a row from the BIP-39 English word list, or 3 or more after a seed-phrase label. Numbering, commas, table pipes and line breaks may sit between the words. The checksum is not tested, so a mistyped or partial phrase is still caught.

- Examples: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` (a published BIP-39 test vector); `1. letter 2. advice 3. cage ... 24. bless`
- Not this class: a wallet address; a Monero, SLIP-39 or non-English phrase (not detected)
- Labels the rules look for: `seed (?:phrase|words?)`, `(?:secret )?recovery (?:phrase|words?|seed)`, `backup (?:phrase|words?|seed)`, `mnemonic(?: phrase| code| words?)?`, `wallet (?:seed|words?|phrase)`, `(?:12|24|twelve|twenty-four)[ -]word (?:phrase|seed|backup|list)`

Ordinary English holds long runs of BIP-39 words ("you know what they say just make this one more time when you want"), so a run stops at a sentence end, a label, a heading, a table rule, a blank line (unless both lines hold one numbered word, as on a seed card) and any code punctuation, and a run is not a seed when more than half its words are common English. A random phrase has about one common word in nine. A label counts only with `:`, `=` or a line break between it and the words. The word list is checked against its pinned sha256 before any document is read.

### `NPI`

Provider identifier. Tier A, placeholder `[NPI_n]`, caught by rules.

A National Provider Identifier, DEA number or other clinician registration number. It identifies the clinician named next to it.

- Examples: `1234567893`
- Labels the rules look for: `npi`, `dea(?: no\.?| number| #)?`, `license(?: no\.?| number| #)`

### `OTHER_ID`

Other identifying number. Tier A, placeholder `[ID_n]`, caught by rules.

The HIPAA catch-all: any other number or code unique to a person or their record, such as a form, claim, case or patient ID.

- Examples: `INTAKE-2026-10-30-0047`
- Not this class: an order number; a dollar amount; a page number
- Labels the rules look for: `form id`, `claim(?: id| no\.?| number| #)`, `case(?: id| no\.?| number| #)`, `patient(?: id| no\.?| number| #)`, `record(?: id| no\.?| number| #)`, `visit(?: id| no\.?| #)`, `encounter(?: id| no\.?| #)`, `employee(?: id| no\.?| #)`, `student(?: id| no\.?| #)`, `customer(?: id| no\.?| #)`, `client(?: id| no\.?| #)`, `id(?: no\.?| #)?`

### `CITY`

City or town. Tier B, placeholder `[CITY_n]`, caught by classifier, llm.

A city, town or neighborhood, anywhere in the document, including inside an organization's name.

- Examples: `Evanston`; `Los Angeles`
- Labels the rules look for: `city`
- Classifier labels: `location city`

### `STATE`

State or province. Tier B, placeholder `[STATE_n]`, caught by rules, classifier, llm.

A US state, territory or province, as a name or a postal code.

- Examples: `IL`; `Illinois`
- Not this class: MI meaning myocardial infarction in a medical history (redacted anyway when it is ambiguous)
- Labels the rules look for: `state`
- Classifier labels: `location state`

### `ZIP`

ZIP or postal code. Tier B, placeholder `[ZIP_n]`, caught by rules, classifier.

A ZIP code or postal code, including ZIP+4.

- Examples: `60201`
- Not this class: a five-digit dollar amount
- Labels the rules look for: `zip(?: code)?`, `postal code`, `postcode`
- Classifier labels: `location zip`

### `AGE`

Age. Tier B, placeholder `[AGE_n]`, caught by rules, classifier.

A person's age at any value.

- Examples: `47`; `age 12`; `72`
- Not this class: a duration such as 'three weeks'
- Labels the rules look for: `age`, `aged`
- Classifier labels: `age`

### `SEX`

Sex or gender. Tier B, placeholder `[SEX_n]`, caught by rules, classifier.

A person's recorded sex or gender identity.

- Examples: `Female`
- Not this class: pronouns, which are kept
- Labels the rules look for: `sex`, `gender`
- Classifier labels: `gender`

### `MARITAL_STATUS`

Marital status. Tier B, placeholder `[MARITAL_n]`, caught by rules, classifier.

A person's marital or partnership status.

- Examples: `Married`
- Not this class: a relationship word such as 'husband' or 'spouse', which is kept
- Labels the rules look for: `marital status`
- Classifier labels: `marital status`

### `OCCUPATION`

Occupation. Tier B, placeholder `[OCCUPATION_n]`, caught by classifier, llm.

A person's job title or occupation.

- Examples: `Senior Data Analyst`
- Not this class: a clinician's credential such as MD or DO after their name
- Labels the rules look for: `occupation`, `job title`, `profession`
- Classifier labels: `occupation`

### `ORGANIZATION`

Organization tied to a person. Tier B, placeholder `[ORG_n]`, caught by classifier, llm.

An employer, care provider, pharmacy, school, bank or other named organization in a document about a person.

- Examples: `Lakeshore Analytics Group, LLC`; `Northside Example Pharmacy #0412`
- Labels the rules look for: `employer`, `company`, `pharmacy`, `bank`, `carrier`, `school`
- Classifier labels: `organization`, `organization medical facility`

### `HEALTH_INFO`

Health content. Tier H, placeholder `[HEALTH_n]`, caught by classifier, llm.

Diagnoses, diagnosis codes, medications, allergies, procedures, test results and blood type. Off in strict: HIPAA de-identification removes identifiers and keeps clinical content, and the document is useless without it.

- Examples: `E11.9`; `Metformin 500 mg`; `Penicillin`; `O+`
- Labels the rules look for: `diagnos[ie]s`, `medications?`, `allerg(?:y|ies)`, `blood type`
- Classifier labels: `condition`, `drug`, `medical code`, `blood type`, `medical process`
