# jwt
## 实现的算法
- HS(256/384/512): 签名和验证  
- RS(256/384/512): 签名和验证  
- ES(256/384/512): 签名和验证  
- PS(256/384/512): 签名和验证  
## 使用方法  
具体用法查看[jwt_test.go](./jwt_test.go)
```
// 签名
s := jwt.NewSigner()
s.Sign()
v := jwt.NewVerifier()
v.Verify()
// 或者直接，内部有缓存管理
jwt.Sign()
jwt.Verify()
``` 
## 测试  
```
goos: darwin
goarch: amd64
pkg: jwt
Benchmark_Sign_HS256-4     	  157210	      7499 ns/op	    1696 B/op	      38 allocs/op
Benchmark_Sign_HS384-4     	  142286	      7451 ns/op	    1712 B/op	      38 allocs/op
Benchmark_Sign_HS512-4     	  143828	      7463 ns/op	    1728 B/op	      38 allocs/op
Benchmark_Sign_RS256-4     	     720	   1701601 ns/op	   48755 B/op	     179 allocs/op
Benchmark_Sign_RS384-4     	     733	   1667448 ns/op	   48776 B/op	     179 allocs/op
Benchmark_Sign_RS512-4     	     704	   1658633 ns/op	   48788 B/op	     179 allocs/op
Benchmark_Sign_ES256-4     	   32388	     37508 ns/op	    4387 B/op	      70 allocs/op
Benchmark_Sign_ES384-4     	     264	   5355431 ns/op	 1745131 B/op	   14435 allocs/op
Benchmark_Sign_ES512-4     	     148	   7850088 ns/op	 3021157 B/op	   19565 allocs/op
Benchmark_Sign_PS256-4     	     744	   1579178 ns/op	   49409 B/op	     185 allocs/op
Benchmark_Sign_PS384-4     	     716	   1614239 ns/op	   49521 B/op	     185 allocs/op
Benchmark_Sign_PS512-4     	     738	   1595885 ns/op	   49536 B/op	     185 allocs/op
Benchmark_Verify_HS256-4   	 7673672	       149 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_HS384-4   	 7536086	       150 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_HS512-4   	 7701712	       151 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_RS256-4   	 7741936	       150 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_RS384-4   	 7722534	       151 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_RS512-4   	 7908459	       154 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_ES256-4   	 7701304	       150 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_ES384-4   	 7813792	       154 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_ES512-4   	 7770724	       166 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_PS256-4   	 7763037	       154 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_PS384-4   	 7849470	       156 ns/op	      32 B/op	       2 allocs/op
Benchmark_Verify_PS512-4   	 7563924	       151 ns/op	      32 B/op	       2 allocs/op
PASS
```