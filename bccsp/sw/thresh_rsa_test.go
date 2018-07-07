package sw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestThreshRSASignerSign(t *testing.T) {
	t.Parallel()

	signer := &threshSigner{}
	verifier := &threshVerifier{}

	// Generate a key share
	mockShare1 := []byte("AAAAAQAAAJAMVssN0DYN8YCDQI2zBEPNgDypiq+xRCpQS4dISjzpN2xa8mUBshUgeKl6zHIJpRancLbiFXoh6i/bMC5iRRqsVXh6od11NWBMx6lhq4QCjGM7GEiNghkEoBL5pF6Qlnwy2Oh0nOyu7n/n9c/3YaABAWVdldmPWWLgoFFgMeL+2B8K0xhCqJ6WjFC2VLCQr3QAAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACARi7NSP/svwt9K6vkuJOKgjdfe0UDFc3qGX4b+uTtkWytOC9GAlRV7YCSeY0YZg5IBfzvf9nuEiL55gxqiDk/9O5G0T1a6bLMxIPsK6tML3KVzRwc4kA4w6DraQAIqVXGhbB/QjvHVqFuATCT+PPpWGVNFsDwjtH3EcQfLuXpie0AAACAMl3/2LGK3BmEzEQoWc+ejD4xLPuwo7KpLkAdjl5eIpKN1WNj4GIH/oQqBG3+NmqG9HlqBsNl0zrVk6n3CJZcaSJm2qI4tfKSQG6h4E/E6Q3Vtc+1TdGRXftLBBSD0l//F3p+iYXprZRlOGGkopJ02wPbSg+unFP9cpLwqMJOWmM=")
	mockShare2 := []byte("AAAAAgAAAJBRJR/v8h80NXOuvlot7e3rPi15y7wM1Z5OgAvzgybrjMvE4wZ0kziD9++Ui8rrGrOJw5/nOp1zjXO9AfBT6vwNXjDeTxMH+IpJH4GdFTwC7uUqk3kWi4tWZEN5Jn9x37uXybXfKuh6IoNTtQvb4/irzs7r5ncc5Y02X7CxPE3CSt0jI8RqbsL6CopIhcKS5vsAAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACACZxCadnjjUrhB8Gvu77ubnHyapUDto6x1dGMW/5Avz3aFyhJoq7BDYrmrDNkf55+I9e+CjTSYMbNM+40X+IvOMte0fxbU817w6xJa95DnsN5UqcDgVoOqXPcQtQB3lUlHiWxK1FupjnevVXsAtT7ek1V+rMpYZCwlSdnQ5ATCAgAAACAQBU19PCctNEj2iUk77WC7sWe7yl/VFE9qrTuDB/uW5GKsOvxjD7KEBawtm0wpeLK1hrwUqwUvfPa+oWwLMhjYhsTVQwnKAc0P2GpyqNLzMhtodF4grbPeZjJDDf0u5acr5Lwpr0/WuyDklCwA/mOyW0jgr45nBtOgu1aKoBv/G8=")
	mockShare3 := []byte("AAAAAwAAAJAo8Mb8TZ0ztOH3UI7iJvRAJSFlKooADuF9P67e+ozIx8+GqJsAO5LmE8f3CD0A4eRCUFr/CxZb0Pgw0IhiW+dWMME51LaHBI1+x/2Nz9+LznYtCF4z0yfGod2YDbb9w7uhk1hxCoPAYTdPxQnxAolXVb+vy8n8kLSVGEDpQoHoacgxISaLM4t3dy8n0rEuMboAAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACAQG2t27SnhePJ1P2WRTE0gV4WbEJsLMGX0zAwa7cH8iVlY9Z8iLcA7sVcqE24XR14pSN74mgzkLz5hYr7pWtnXiBqk8JG4U0v6B5Vfe8ztcsMHzN2htIf1XgycjprmSy9hCRdyQ3rV8zq6M3zE1aMy9aNK+CxyJcZEv7t2FsfcUIAAACAODUgTeIhkbnCPkAjEDuEBd3H36YwJh2C9hvowItudSOJTVgtKRK7PqG1XMB0T7d18dI2Ay/JCm9Jz0OhTm17F8NGnFi2STBRBzUw0W1jY+1/U9olgdi6JQtMwGyK45A+KE/FBP1JYuWiqqgPFWqTZl7aj+57QWaj/NAZc5xfl/U=")
	mockShare4 := []byte("AAAABAAAAJAtNeSFaop1N/bMqnMJNnbsnxFpe6B8HwqWOTHO93jomIw/uB5g8QPGWUB9gUFy9KiPPn7Tc+R4zBK8dgyP0U2SIdHqjZLIka0M8izNrxZieA0kktn5dvIVxM9hspjpRGSy/gvlwaj3gFnnG21fbKQLl8QSiPNhRhjouJhLGeZ+NJSdf6mascCsRW5CTMXWursAAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACAFPEsR9s5q8TV0xYOY5RmVTM6V8qt2IP40QyLkVMEc9odAZA3txeohl8Yh3bjo7wynqwOO5e//JTz27teApOGPufcxcdnB1TXG8tziNeWOyoNCfPCiyjWozqP4dabiFPIxl+p7Hv3+tfv5vIr7YUM2LKlcYfAQZk750ljsZkIszQAAACAGQvZRApOPD/Sg5RDIjD5ipp0WpqmAiVVJ9WzeiqEuJkcgflzE3biM9Hc/e1KE+p6YKz8/tPwKHqpjxQUMFijytzCB69rmg/XyeNDMavDlvF10WIzPZ+S8MEuxioyLiGH3C8J9hotNDtfDZTrxh1FTO+ZNPmYRi2Z4RLLNB+ylr0=")
	// obs: mockshare 6 missing on purpose
	mockShare6 := []byte("AAAABgAAAJAi7XOuZ/4xJsQiUzNxaSpLEJ/kCPDMcD9lRPkKsWt9kWYcM4AGugtycMektPHPzcxHJybmbfk23IRcsz8ej30ycm02vgAlFvRMMTP+gzK7TOToH0sXTQQ3pBlqQcOI0VlZ6XidiLfv5O1mf0CaxqAZ/Mqku+ybd5LBdxOzYS5DV+4kVpLmiGfVY2NRT1/MER8AAACAXJAPiQQVmP1Vcbkg9jNzylOh6TSqvgmkP/Ywql9of9waEBg6EydMoFqiZUsFAq5GJemP8ztyNNdNELCSStNzaMcr198Yz8IRPKjuF2VHQqnj08sKvuWEvgeuyLjJV+u7OScZM8wmyb74usfVSE/6WC3VnjsLQC1btDxGjBNkfq0AAAACAtAAAACAJxpMhKYCx8+EzlCY+s+SazXZzNHD2fh6qEVFvNrFgXzKfassi8Xq0kHYaF9i22iTaSfcUgpELtcDnnMhLKlHVv4djC2KjAKZXIDpR3UnwB3P6MSqGSo8u3ZKX/gEwBngll/04WAhmqZ439tEZ6Jh83UZGDB6JLDbmk7BMm4bKfMAAACAONouetK5T42RfTcLpukd8SmIn4D7c3bERj2CCwbBg4lEGFRgsNgKSBtyIZFBZN5fF5409Zv3n7xS4r9WFIV45ldZyIxOdqT3+J92nhDttJZJ6fpVo5VjT722xixg0jFU6cUK6M/5PixcCC914wN9duWLFw2pQ8Hcc+OgxO6Y9TA=")
	mockGk := []byte("AAAABQAAAAYAAAADAQABAAAAgFyQD4kEFZj9VXG5IPYzc8pToek0qr4JpD/2MKpfaH/cGhAYOhMnTKBaomVLBQKuRiXpj/M7cjTXTRCwkkrTc2jHK9ffGM/CETyo7hdlR0Kp49PLCr7lhL4Hrsi4yVfruzknGTPMJsm++LrH1UhP+lgt1Z47C0AtW7Q8RowTZH6t")

	gk := &threshRsaGroupKey{&threshRsaGroupKeyASN{L: 6, K: 5, GroupKeyBytes: mockGk}}
	ks1 := &threshRsaKeyShare{Id: 1, KeyShareBytes: mockShare1, GroupKey: gk.groupKey}
	ks2 := &threshRsaKeyShare{Id: 2, KeyShareBytes: mockShare2, GroupKey: gk.groupKey}
	ks3 := &threshRsaKeyShare{Id: 3, KeyShareBytes: mockShare3, GroupKey: gk.groupKey}
	ks4 := &threshRsaKeyShare{Id: 4, KeyShareBytes: mockShare4, GroupKey: gk.groupKey}
	ks6 := &threshRsaKeyShare{Id: 6, KeyShareBytes: mockShare6, GroupKey: gk.groupKey}

	// Sign
	msg := []byte("Hello World!!!")

	signedMsg1, err := signer.Sign(ks1, msg, nil)
	assert.NoError(t, err)
	t.Logf("Got the following signed message from id %d: %s", ks1.Id, signedMsg1)

	signedMsg2, err := signer.Sign(ks2, msg, nil)
	assert.NoError(t, err)
	t.Logf("Got the following signed message from id %d: %s", ks2.Id, signedMsg2)

	signedMsg3, err := signer.Sign(ks3, msg, nil)
	assert.NoError(t, err)
	t.Logf("Got the following signed message from id %d: %s", ks3.Id, signedMsg3)

	signedMsg4, err := signer.Sign(ks4, msg, nil)
	assert.NoError(t, err)
	t.Logf("Got the following signed message from id %d: %s", ks4.Id, signedMsg4)

	signedMsg6, err := signer.Sign(ks6, msg, nil)
	assert.NoError(t, err)
	t.Logf("Got the following signed message from id %d: %s", ks6.Id, signedMsg6)

	var sigs = make([][]byte, gk.groupKey.K, gk.groupKey.L)
	sigs[0] = signedMsg1
	sigs[1] = signedMsg2
	sigs[2] = signedMsg3
	sigs[3] = signedMsg4
	sigs[4] = signedMsg6

	// Verify against msg, must pass
	result, err := verifier.Verify(gk, sigs, msg, nil)
	assert.NoError(t, err)

	t.Logf("Verification ended. Result is: %t", result)

}
