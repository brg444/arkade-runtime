package application

// ProposedEnrollment is the descriptor the tenant must sign before Finish.
type ProposedEnrollment struct {
	VaultID        string `json:"vaultId"`
	DescriptorHash string `json:"descriptorHash"`
	Descriptor     any    `json:"descriptor"`
}
