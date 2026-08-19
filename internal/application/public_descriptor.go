package application

// Leftover v4 public schema. Live enrolls hash arkade-vault/v5 descriptors.
const publicDescriptorSchema = "arkade-vault/v4"

// ProposedEnrollment is the descriptor the tenant must sign before Finish.
type ProposedEnrollment struct {
	VaultID        string `json:"vaultId"`
	DescriptorHash string `json:"descriptorHash"`
	Descriptor     any    `json:"descriptor"`
}
