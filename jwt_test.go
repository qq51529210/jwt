package jwt

import (
	"bytes"
	"strings"
	"testing"
)

// 测试签名和验证
func Test_SignAndVerify(t *testing.T) {
	pro := NewDefaultProvider("hs256", "hs384", "hs512")
	alg := []Alg{
		"HS256",
		"HS384",
		"HS512",
		"RS256",
		"RS384",
		"RS512",
		"ES256",
		"ES384",
		"ES512",
		"PS256",
		"PS384",
		"PS512",
	}
	var buffer strings.Builder
	header := make(Claims)
	header["test1"] = 1
	header["test2"] = "2"
	payload := make(Claims)
	payload["test3"] = 3
	payload["test4"] = "4"
	for i := 0; i < len(alg); i++ {
		buffer.Reset()
		err := SignTo(&buffer, alg[i], header, payload, pro)
		if err != nil {
			t.Fatal(err)
		}
		h, p, e := Verify(buffer.String(), pro)
		if e != nil {
			t.Fatal(e)
		}
		v1, o := h["test1"].(float64)
		if !o || v1 != 1 {
			t.FailNow()
		}
		v2, o := h["test2"].(string)
		if !o || v2 != "2" {
			t.FailNow()
		}
		v1, o = p["test3"].(float64)
		if !o || v1 != 3 {
			t.FailNow()
		}
		v2, o = p["test4"].(string)
		if !o || v2 != "4" {
			t.FailNow()
		}
	}
}

func benchmarkSign(b *testing.B, a Alg) {
	pro := NewDefaultProvider("hs256", "hs384", "hs512")
	var buf bytes.Buffer
	header := make(map[string]interface{})
	header["test1"] = "test1"
	header["test2"] = "test2"
	payload := make(map[string]interface{})
	payload["test1"] = "test1"
	payload["test2"] = "test2"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = SignTo(&buf, a, header, payload, pro)
	}
}

func Benchmark_Sign_HS256(b *testing.B) {
	benchmarkSign(b, "HS256")
}

func Benchmark_Sign_HS384(b *testing.B) {
	benchmarkSign(b, "HS384")
}

func Benchmark_Sign_HS512(b *testing.B) {
	benchmarkSign(b, "HS512")
}

func Benchmark_Sign_ES256(b *testing.B) {
	benchmarkSign(b, "ES256")
}

func Benchmark_Sign_ES384(b *testing.B) {
	benchmarkSign(b, "ES384")
}

func Benchmark_Sign_ES512(b *testing.B) {
	benchmarkSign(b, "ES512")
}

func Benchmark_Sign_RS256(b *testing.B) {
	benchmarkSign(b, "RS256")
}

func Benchmark_Sign_RS384(b *testing.B) {
	benchmarkSign(b, "RS384")
}

func Benchmark_Sign_RS512(b *testing.B) {
	benchmarkSign(b, "RS512")
}

func Benchmark_Sign_PS256(b *testing.B) {
	benchmarkSign(b, "PS256")
}

func Benchmark_Sign_PS384(b *testing.B) {
	benchmarkSign(b, "PS384")
}

func Benchmark_Sign_PS512(b *testing.B) {
	benchmarkSign(b, "PS512")
}

func benchmarkVerify(b *testing.B, a Alg) {
	pro := NewDefaultProvider("hs256", "hs384", "hs512")
	header := make(map[string]interface{})
	header["test1"] = "test1"
	header["test2"] = "test2"
	payload := make(map[string]interface{})
	payload["test1"] = "test1"
	payload["test2"] = "test2"
	b.ReportAllocs()
	b.ResetTimer()
	var buf strings.Builder
	_ = SignTo(&buf, a, header, payload, pro)
	str := buf.String()
	for i := 0; i < b.N; i++ {
		_, _, _ = Verify(str, pro)
	}
}

func Benchmark_Verify_HS256(b *testing.B) {
	benchmarkVerify(b, "HS256")
}

func Benchmark_Verify_HS384(b *testing.B) {
	benchmarkVerify(b, "HS384")
}

func Benchmark_Verify_HS512(b *testing.B) {
	benchmarkVerify(b, "HS512")
}

func Benchmark_Verify_ES256(b *testing.B) {
	benchmarkVerify(b, "ES256")
}

func Benchmark_Verify_ES384(b *testing.B) {
	benchmarkVerify(b, "ES384")
}

func Benchmark_Verify_ES512(b *testing.B) {
	benchmarkVerify(b, "ES512")
}

func Benchmark_Verify_RS256(b *testing.B) {
	benchmarkVerify(b, "RS256")
}

func Benchmark_Verify_RS384(b *testing.B) {
	benchmarkVerify(b, "RS384")
}

func Benchmark_Verify_RS512(b *testing.B) {
	benchmarkVerify(b, "RS512")
}

func Benchmark_Verify_PS256(b *testing.B) {
	benchmarkVerify(b, "PS256")
}

func Benchmark_Verify_PS384(b *testing.B) {
	benchmarkVerify(b, "PS384")
}

func Benchmark_Verify_PS512(b *testing.B) {
	benchmarkVerify(b, "PS512")
}
