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

* Testing variant: x4_scalar_iv_mem_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4586000 EVP-AES-128-GCM encrypt init operations in 1000218us (4585000.5 ops/sec)
Did 7992250 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000016us (7992122.1 ops/sec): 127.9 MB/s     + 8.4%
Did 4851750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000020us (4851653.0 ops/sec): 1242.0 MB/s   +11.5%
Did 1644750 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000096us (1644592.1 ops/sec): 2220.2 MB/s  +21.0%
Did 347000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002653us (346081.8 ops/sec): 2835.1 MB/s    +28.2%
Did 177000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001611us (176715.3 ops/sec): 2895.3 MB/s   +28.8%
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
* Testing variant: x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4713000 EVP-AES-192-GCM encrypt init operations in 1000208us (4712019.9 ops/sec)
Did 7854500 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000009us (7854429.3 ops/sec): 125.7 MB/s
Did 4535500 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000025us (4535386.6 ops/sec): 1161.1 MB/s
Did 1463250 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000127us (1463064.2 ops/sec): 1975.1 MB/s
Did 298000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1000327us (297902.6 ops/sec): 2440.4 MB/s
Did 152000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1002068us (151686.3 ops/sec): 2485.2 MB/s

* Testing variant: x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4667000 EVP-AES-192-GCM encrypt init operations in 1000145us (4666323.4 ops/sec)
Did 7881750 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000029us (7881521.4 ops/sec): 126.1 MB/s     + 8.7%
Did 4526250 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000014us (4526186.6 ops/sec): 1158.7 MB/s   + 9.3%
Did 1464000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000387us (1463433.7 ops/sec): 1975.6 MB/s  +15.2%
Did 299000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1002508us (298252.0 ops/sec): 2443.3 MB/s    +19.1%
Did 152000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1000833us (151873.5 ops/sec): 2488.3 MB/s   +19.5%

* Testing variant: x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4677000 EVP-AES-192-GCM encrypt init operations in 1000023us (4676892.4 ops/sec)
Did 7889000 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000114us (7888100.8 ops/sec): 126.2 MB/s
Did 4451750 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000014us (4451687.7 ops/sec): 1139.6 MB/s
Did 1430000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000236us (1429662.6 ops/sec): 1930.0 MB/s
Did 289000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1002697us (288222.7 ops/sec): 2361.1 MB/s
Did 147000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1001238us (146818.2 ops/sec): 2405.5 MB/s
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
Did 4540000 EVP-AES-256-GCM encrypt init operations in 1000064us (4539709.5 ops/sec)
Did 7628750 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000027us (7628544.0 ops/sec): 122.1 MB/s
Did 4250000 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000013us (4249944.8 ops/sec): 1088.0 MB/s
Did 1335000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000529us (1334294.2 ops/sec): 1801.3 MB/s
Did 267000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1002147us (266428.0 ops/sec): 2182.6 MB/s
Did 136000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1004652us (135370.3 ops/sec): 2217.9 MB/s

SLOTHY expectations:
// Instructions:    131
// Expected cycles: 70
// Expected IPC:    0.5343511450381679

SLOTHY expectation would correspond to:
- 64/70 * 2.5ghz = 2.28gb/s

* Testing variant: x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4543000 EVP-AES-256-GCM encrypt init operations in 1000184us (4542164.2 ops/sec)
Did 7634250 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000002us (7634234.7 ops/sec): 122.1 MB/s         +10.0%
Did 4262000 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000230us (4261020.0 ops/sec): 1090.8 MB/s       + 8.5%
Did 1338000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000192us (1337743.2 ops/sec): 1806.0 MB/s      +14.6%
Did 268000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1001890us (267494.4 ops/sec): 2191.3 MB/s        +17.9%
Did 136000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1000111us (135984.9 ops/sec): 2228.0 MB/s       +18.1%

SLOTHY expectations:
// Instructions:    130
// Expected cycles: 70
// Expected IPC:    0.5384615384615384

SLOTHY expectations would correspond to:
- 64/70 * 2.5ghz = 2.28gb/s

* Testing variant: x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4546000 EVP-AES-256-GCM encrypt init operations in 1000094us (4545572.7 ops/sec)
Did 7716500 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000011us (7716415.1 ops/sec): 123.5 MB/s
Did 4226500 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000029us (4226377.4 ops/sec): 1082.0 MB/s
Did 1318250 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000048us (1318186.7 ops/sec): 1779.6 MB/s
Did 263000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1001114us (262707.3 ops/sec): 2152.1 MB/s
Did 134000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1003098us (133586.2 ops/sec): 2188.7 MB/s

SLOTHY expectations:
// Instructions:    139
// Expected cycles: 70
// Expected IPC:    0.5035971223021583

SLOTHY expectations would correspond to:
- 64/70 * 2.5ghz = 2.28gb/s
```
