package internal

type PairState string

const (
	StateUnpaired PairState = "unpaired"
	StatePaired   PairState = "paired"
	StateExpired  PairState = "expired"
)
