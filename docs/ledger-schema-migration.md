# Historical account storage retirement

Schema 12 keeps shared Spending and Ledger Savings records while removing both
connector stores, the obsolete `recovery_session` store, and accounts whose
authenticated template identifies either connector generation, historical
`vaulted-light-v1`, or direct-hardware `phone-hww-recovery-savings-v1`. The exact schema 11 baseline is the only supported
upgrade source, and schemas 1 through 10 fail admission.

Opening an existing database validates its complete schema without upgrading
it. Installing the integrity key revalidates schema 11 inside a transaction,
authenticates every account descriptor and credential, and selects discarded
accounts only after descriptor verification. Shared operations, events,
recovery material and sign counters are also authenticated before their
correlation fields can determine deletion. This prevents a database writer
from redirecting a retained signed payment into a discarded account and
concealing its removal in the sequence base. The transaction drops
both connector tables and `recovery_session`, removes the selected accounts and their owned records,
and advances the schema version. Retained records and their existing MACs are
unchanged. A failed transaction leaves schema 11 and its records intact.

The economic sequence previously counted connector operations and other
operation rows owned by retired accounts. Schema 12 stores the removed count
in one authenticated `policy_sequence_base` row. Its MAC binds the network and
unsigned 64-bit base to the new `arkade-vault/policy-sequence-base/v1` domain.
The row contains a count, with no account, transaction or signing authority.
Future sequence observations add that base to the retained economic row count.
The external sequence keeps its existing format, MAC domain, value and write
ordering. Retirement never rewrites it; startup still rejects a missing
required sequence or a database behind it.

The removed recovery table has no retained callers and contributes no economic
sequence count. Its rows are discarded as a whole, without decoding or resuming
their programs. Ledger Savings keeps its separate authenticated recovery event
journal, existing record encoding and replay rules.

A fresh schema 12 database creates only current stores and seals a zero base
when its first integrity key is installed. An enrolled database with a missing
base fails startup. A changed value, MAC, network or key fails authentication.
An older database replayed through retirement remains behind any later activity
recorded by the independently preserved external sequence.

The policy tests use fixed schema 11 captures from runtime `91067dde` for both
networks. They cover retained identity, sign counts, signed payments, backups,
Ledger recovery, renewal, delegation, boarding conflict history, transaction
abort, malformed source schemas, account substitution and independent sequence
rollback. Current schema goldens record the deliberate schema 12 baseline;
retained signing, derivation and row-MAC vectors remain unchanged. Tests also
reject corrupted records in all 19 shared stores inspected during retirement,
authenticated journal payloads with changed SQL correlation fields, and
retained payments redirected onto a discarded account.

Release qualification must bind the schema 12 runtime to matching Contract
Packs, wallet and recovery inputs before activation. Production backup,
storage-failure, rollback and funded lifecycle qualification remain separate
release work. A binary that supports only schema 11 cannot read the upgraded
database. Restoring an older database after new activity would discard that
activity and remains incompatible with the later independent sequence.
