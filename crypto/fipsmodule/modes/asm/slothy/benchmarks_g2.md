# Benchmarks: Graviton 2

## AES-128-GCM

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
Did 4767000 EVP-AES-128-GCM encrypt init operations in 1000042us (4766799.8 ops/sec)
Did 7403000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000006us (7402955.6 ops/sec):   118.4 MB/s
Did 4358000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000134us (4357416.1 ops/sec):  1115.5 MB/s
Did 1360000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000632us (1359141.0 ops/sec): 1834.8 MB/s
Did 270000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000588us (269841.3 ops/sec):   2210.5 MB/s
Did 138000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006107us (137162.3 ops/sec):  2247.3 MB/s
```

### SLOTHY

```
* Testing variant: x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4720000 EVP-AES-128-GCM encrypt init operations in 1000151us (4719287.4 ops/sec)
Did 8131000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000024us (8130804.9 ops/sec):   130.1 MB/s
Did 4723250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000041us (4723056.4 ops/sec):  1209.1 MB/s
Did 1542000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000115us (1541822.7 ops/sec): 2081.5 MB/s
Did 314000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002600us (313185.7 ops/sec):   2565.6 MB/s
Did 160000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003209us (159488.2 ops/sec):  2613.1 MB/s
* Testing variant: x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4706000 EVP-AES-128-GCM encrypt init operations in 1000124us (4705416.5 ops/sec)
Did 8093250 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000025us (8093047.7 ops/sec):   129.5 MB/s
Did 4764500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000006us (4764471.4 ops/sec):  1219.7 MB/s
Did 1559500 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000070us (1559390.8 ops/sec): 2105.2 MB/s
Did 323000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002939us (322053.5 ops/sec):   2638.3 MB/s
Did 165000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001290us (164787.4 ops/sec):  2699.9 MB/s
* Testing variant: x4_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4722000 EVP-AES-128-GCM encrypt init operations in 1000117us (4721447.6 ops/sec)
Did 8060750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000025us (8060548.5 ops/sec):   129.0 MB/s
Did 4737750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000011us (4737697.9 ops/sec):  1212.9 MB/s
Did 1574000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000206us (1573675.8 ops/sec): 2124.5 MB/s
Did 320000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001713us (319452.8 ops/sec):   2617.0 MB/s
Did 163000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001344us (162781.2 ops/sec):  2667.0 MB/s
* Testing variant: x4_dual_acc_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4718000 EVP-AES-128-GCM encrypt init operations in 1000056us (4717735.8 ops/sec)
Did 8048750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000013us (8048645.4 ops/sec):   128.8 MB/s    + 8.4%
Did 4857000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000176us (4856145.3 ops/sec):  1243.2 MB/s   +11.5%
Did 1617000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000521us (1616158.0 ops/sec): 2181.8 MB/s   +18.9%
Did 335000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001923us (334357.0 ops/sec):   2739.1 MB/s   +23.9%
Did 171000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002551us (170564.9 ops/sec):  2794.5 MB/s   +24.3%
```

## AES-192-GCM

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
Did 4638000 EVP-AES-192-GCM encrypt init operations in 1000052us (4637758.8 ops/sec)
Did 7212250 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000023us (7212084.1 ops/sec):   115.4 MB/s
Did 4139250 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000016us (4139183.8 ops/sec):  1059.6 MB/s
Did 1270000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000450us (1269428.8 ops/sec): 1713.7 MB/s
Did 251000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1002815us (250295.4 ops/sec):   2050.4 MB/s
Did 128000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1007080us (127100.1 ops/sec):  2082.4 MB/s
```

### SLOTHY

```
* Testing variant: x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4690000 EVP-AES-192-GCM encrypt init operations in 1000189us (4689113.8 ops/sec)
Did 7826500 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000026us (7826296.5 ops/sec):   125.2 MB/s
Did 4446000 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000041us (4445817.7 ops/sec):  1138.1 MB/s
Did 1413000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000259us (1412634.1 ops/sec): 1907.1 MB/s
Did 283000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1002500us (282294.3 ops/sec):   2312.6 MB/s
Did 144000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1001812us (143739.5 ops/sec):  2355.0 MB/s
* Testing variant: x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4713000 EVP-AES-192-GCM encrypt init operations in 1000022us (4712896.3 ops/sec)
Did 7898000 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000016us (7897873.6 ops/sec):   126.4 MB/s     + 9.5%
Did 4412000 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000019us (4411916.2 ops/sec):  1129.5 MB/s    + 6.6%
Did 1411000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000051us (1410928.0 ops/sec): 1904.8 MB/s    +11.1%
Did 286000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1000653us (285813.4 ops/sec):   2341.4 MB/s    +14.2%
Did 146000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1001567us (145771.6 ops/sec):  2388.3 MB/s    +14.6%
```

## AES-256-GCM

### AWS-LC

```
Did 4578500 EVP-AES-256-GCM encrypt init operations in 1000046us (4578289.4 ops/sec)
Did 6974000 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000013us (6973909.3 ops/sec):   111.6 MB/s
Did 3925000 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000122us (3924521.2 ops/sec):  1004.7 MB/s
Did 1168000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000430us (1167498.0 ops/sec): 1576.1 MB/s
Did 228000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1004311us (227021.3 ops/sec):   1859.8 MB/s
Did 116000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1007694us (115114.3 ops/sec):  1886.0 MB/s
```

### SLOTHY

```
* Testing variant: x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4558000 EVP-AES-256-GCM encrypt init operations in 1000111us (4557494.1 ops/sec)
Did 7623250 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000019us (7623105.2 ops/sec):   122.0 MB/s
Did 4154250 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000008us (4154216.8 ops/sec):  1063.5 MB/s
Did 1283000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000623us (1282201.2 ops/sec): 1731.0 MB/s
Did 252000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1003554us (251107.6 ops/sec):   2057.1 MB/s
Did 128000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1002387us (127695.2 ops/sec):  2092.2 MB/s
* Testing variant: x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4530000 EVP-AES-256-GCM encrypt init operations in 1000177us (4529198.3 ops/sec)
Did 7573250 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000025us (7573060.7 ops/sec):   121.2 MB/s
Did 4259500 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000003us (4259487.2 ops/sec):  1090.4 MB/s
Did 1337000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000482us (1336355.9 ops/sec): 1804.1 MB/s
Did 268000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1002398us (267358.9 ops/sec):   2190.2 MB/s
Did 136000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1000287us (135961.0 ops/sec):  2227.6 MB/s
* Testing variant: x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4569000 EVP-AES-256-GCM encrypt init operations in 1000171us (4568218.8 ops/sec)
Did 7670500 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000030us (7670269.9 ops/sec):   122.7 MB/s      + 9.9%
Did 4244500 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000045us (4244309.0 ops/sec):  1086.5 MB/s     + 8.1%
Did 1339000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000587us (1338214.5 ops/sec): 1806.6 MB/s     +14.6%
Did 267000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1001554us (266585.7 ops/sec):   2183.9 MB/s     +17.4%
Did 136000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1000491us (135933.3 ops/sec):  2227.1 MB/s     +18.1%
```
