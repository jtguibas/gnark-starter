package tutorial

import (
	. "gnark-ed25519/field"
	"gnark-ed25519/utils"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type TestCircuit struct {
	In  [12]frontend.Variable
	Out [12]frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	var output [12]frontend.Variable
	for i := 0; i < 12; i++ {
		output[i] = api.Add(circuit.In[i], 1)
	}

	for i := 0; i < 12; i++ {
		api.AssertIsEqual(output[i], circuit.Out[i])
	}

	return nil
}

func TestWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [12]frontend.Variable, out [12]frontend.Variable) {
		circuit := TestCircuit{In: in, Out: out}
		witness := TestCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}
	outStr := []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}

func TestProof(t *testing.T) {
	inStr := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}
	outStr := []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], utils.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], utils.StrArrayToFrontendVariableArray(outStr))

	circuit := TestCircuit{In: in, Out: out}
	assignment := TestCircuit{In: in, Out: out}

	r1cs, err := frontend.Compile(TEST_CURVE.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	err = test.IsSolved(&circuit, &assignment, TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
