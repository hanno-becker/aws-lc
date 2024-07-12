# Benchmarks: Graviton 2

## AES-128-GCM Encrypt

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
* Testing variant: aws-lc/128_x4_main
Did 4767000 EVP-AES-128-GCM encrypt init operations in 1000042us (4766799.8 ops/sec)
Did 7403000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000006us (7402955.6 ops/sec):   118.4 MB/s
Did 4358000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000134us (4357416.1 ops/sec):  1115.5 MB/s
Did 1360000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000632us (1359141.0 ops/sec): 1834.8 MB/s
Did 270000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000588us (269841.3 ops/sec):   2210.5 MB/s
Did 138000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006107us (137162.3 ops/sec):  2247.3 MB/s
```

### SLOTHY (optimized)

NOTE: The optimizations below were run with a low timeout of 30min per SLOTHY run. See the optimized
assembly files for the estimated optimal performance, and potentially re-run the optimizer with a
larger time budget.

```
* Testing variant: opt/128_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4713000 EVP-AES-128-GCM encrypt init operations in 1000040us (4712811.5 ops/sec)
Did 8115000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000063us (8114488.8 ops/sec): 129.8 MB/s
Did 4694250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000045us (4694038.8 ops/sec): 1201.7 MB/s
Did 1532000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000568us (1531130.3 ops/sec): 2067.0 MB/s
Did 310000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001812us (309439.3 ops/sec): 2534.9 MB/s
Did 158000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002468us (157611.0 ops/sec): 2582.3 MB/s
* Testing variant: opt/128_x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4720000 EVP-AES-128-GCM encrypt init operations in 1000208us (4719018.4 ops/sec)
Did 8122500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000029us (8122264.5 ops/sec): 130.0 MB/s
Did 4788250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000004us (4788230.8 ops/sec): 1225.8 MB/s
Did 1600000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000239us (1599617.7 ops/sec): 2159.5 MB/s
Did 331000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001022us (330662.1 ops/sec): 2708.8 MB/s
Did 169000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002832us (168522.7 ops/sec): 2761.1 MB/s
* Testing variant: opt/128_x4_dual_acc_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4729000 EVP-AES-128-GCM encrypt init operations in 1000183us (4728134.8 ops/sec)
Did 8057000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000053us (8056573.0 ops/sec): 128.9 MB/s
Did 4868250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000027us (4868118.6 ops/sec): 1246.2 MB/s
Did 1626750 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000112us (1626567.8 ops/sec): 2195.9 MB/s
Did 338000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002362us (337203.5 ops/sec): 2762.4 MB/s
Did 173000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1005519us (172050.5 ops/sec): 2818.9 MB/s
* Testing variant: opt/128_x4_ilp
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4718000 EVP-AES-128-GCM encrypt init operations in 1000150us (4717292.4 ops/sec)
Did 7981000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000021us (7980832.4 ops/sec): 127.7 MB/s
Did 4720000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000044us (4719792.3 ops/sec): 1208.3 MB/s
Did 1571000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000534us (1570161.5 ops/sec): 2119.7 MB/s
Did 324000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002998us (323031.6 ops/sec): 2646.3 MB/s
Did 165000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001960us (164677.2 ops/sec): 2698.1 MB/s
* Testing variant: opt/128_x4_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4722000 EVP-AES-128-GCM encrypt init operations in 1000133us (4721372.1 ops/sec)
Did 8030500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000026us (8030291.2 ops/sec): 128.5 MB/s
Did 4826000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000055us (4825734.6 ops/sec): 1235.4 MB/s
Did 1591000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000033us (1590947.5 ops/sec): 2147.8 MB/s
Did 332000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000223us (331926.0 ops/sec): 2719.1 MB/s
Did 170000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1004473us (169243.0 ops/sec): 2772.9 MB/s
* Testing variant: opt/128_x4_keep_htable_rotate
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4697000 EVP-AES-128-GCM encrypt init operations in 1000173us (4696187.6 ops/sec)
Did 7214000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000008us (7213942.3 ops/sec): 115.4 MB/s
Did 4524000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000203us (4523081.8 ops/sec): 1157.9 MB/s
Did 1592000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000334us (1591468.4 ops/sec): 2148.5 MB/s
Did 336000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002639us (335115.6 ops/sec): 2745.3 MB/s
Did 172000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1004174us (171285.1 ops/sec): 2806.3 MB/s
* Testing variant: opt/128_x4_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4719000 EVP-AES-128-GCM encrypt init operations in 1000100us (4718528.1 ops/sec)
Did 8066500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000016us (8066370.9 ops/sec): 129.1 MB/s
Did 4691000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000098us (4690540.3 ops/sec): 1200.8 MB/s
Did 1531000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000562us (1530140.1 ops/sec): 2065.7 MB/s
Did 313000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002315us (312277.1 ops/sec): 2558.2 MB/s
Did 159000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1000392us (158937.7 ops/sec): 2604.0 MB/s
* Testing variant: opt/128_x4_reload_round_keys_full
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4727000 EVP-AES-128-GCM encrypt init operations in 1000020us (4726905.5 ops/sec)
Did 8124500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000016us (8124370.0 ops/sec): 130.0 MB/s
Did 4724000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000095us (4723551.3 ops/sec): 1209.2 MB/s
Did 1549500 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000157us (1549256.8 ops/sec): 2091.5 MB/s
Did 317000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001082us (316657.4 ops/sec): 2594.1 MB/s
Did 162000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003834us (161381.3 ops/sec): 2644.1 MB/s
* Testing variant: opt/128_x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4714000 EVP-AES-128-GCM encrypt init operations in 1000145us (4713316.6 ops/sec)
Did 8171500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000017us (8171361.1 ops/sec): 130.7 MB/s
Did 4721000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000016us (4720924.5 ops/sec): 1208.6 MB/s
Did 1501000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000076us (1500885.9 ops/sec): 2026.2 MB/s
Did 311000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001319us (310590.3 ops/sec): 2544.4 MB/s
Did 159000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003465us (158451.0 ops/sec): 2596.1 MB/s
* Testing variant: opt/128_x4_scalar_iv
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4727000 EVP-AES-128-GCM encrypt init operations in 1000023us (4726891.3 ops/sec)
Did 8054000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000086us (8053307.4 ops/sec): 128.9 MB/s
Did 4711750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000019us (4711660.5 ops/sec): 1206.2 MB/s
Did 1534000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000156us (1533760.7 ops/sec): 2070.6 MB/s
Did 317000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002604us (316176.7 ops/sec): 2590.1 MB/s
Did 162000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1004324us (161302.5 ops/sec): 2642.8 MB/s
* Testing variant: opt/128_x4_scalar_iv2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4730000 EVP-AES-128-GCM encrypt init operations in 1000207us (4729021.1 ops/sec)
Did 8044750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000020us (8044589.1 ops/sec): 128.7 MB/s
Did 4687000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000031us (4686854.7 ops/sec): 1199.8 MB/s
Did 1517000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000056us (1516915.1 ops/sec): 2047.8 MB/s
Did 312000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001024us (311680.8 ops/sec): 2553.3 MB/s
Did 159000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1000601us (158904.5 ops/sec): 2603.5 MB/s
* Testing variant: opt/128_x4_scalar_iv2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4712000 EVP-AES-128-GCM encrypt init operations in 1000061us (4711712.6 ops/sec)
Did 8027500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000006us (8027451.8 ops/sec): 128.4 MB/s
Did 4695250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000023us (4695142.0 ops/sec): 1202.0 MB/s
Did 1545000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000492us (1544240.2 ops/sec): 2084.7 MB/s
Did 317000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000172us (316945.5 ops/sec): 2596.4 MB/s
Did 162000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003190us (161484.9 ops/sec): 2645.8 MB/s
* Testing variant: opt/128_x4_scalar_iv2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4721000 EVP-AES-128-GCM encrypt init operations in 1000069us (4720674.3 ops/sec)
Did 8021750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000021us (8021581.5 ops/sec): 128.3 MB/s
Did 4699250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000027us (4699123.1 ops/sec): 1203.0 MB/s
Did 1549000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000065us (1548899.3 ops/sec): 2091.0 MB/s
Did 318000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002471us (317216.2 ops/sec): 2598.6 MB/s
Did 162000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003250us (161475.2 ops/sec): 2645.6 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4726000 EVP-AES-128-GCM encrypt init operations in 1000002us (4725990.5 ops/sec)
Did 8016500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000021us (8016331.7 ops/sec): 128.3 MB/s
Did 4824750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000016us (4824672.8 ops/sec): 1235.1 MB/s
Did 1625000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000082us (1624866.8 ops/sec): 2193.6 MB/s
Did 342000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001658us (341433.9 ops/sec): 2797.0 MB/s
Did 175000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1005598us (174025.8 ops/sec): 2851.2 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4720000 EVP-AES-128-GCM encrypt init operations in 1000176us (4719169.4 ops/sec)
Did 7407250 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000009us (7407183.3 ops/sec): 118.5 MB/s
Did 4528500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000039us (4528323.4 ops/sec): 1159.3 MB/s
Did 1604750 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000021us (1604716.3 ops/sec): 2166.4 MB/s
Did 343000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000337us (342884.4 ops/sec): 2808.9 MB/s
Did 176000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1000352us (175938.1 ops/sec): 2882.6 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4718000 EVP-AES-128-GCM encrypt init operations in 1000157us (4717259.4 ops/sec)
Did 7440000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000084us (7439375.1 ops/sec): 119.0 MB/s
Did 4384000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000080us (4383649.3 ops/sec): 1122.2 MB/s
Did 1477000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000020us (1476970.5 ops/sec): 1993.9 MB/s
Did 308000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000360us (307889.2 ops/sec): 2522.2 MB/s
Did 158000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1005629us (157115.6 ops/sec): 2574.2 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4724000 EVP-AES-128-GCM encrypt init operations in 1000022us (4723896.1 ops/sec)
Did 8032000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000027us (8031783.1 ops/sec): 128.5 MB/s
Did 4820500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000037us (4820321.6 ops/sec): 1234.0 MB/s
Did 1623000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000605us (1622018.7 ops/sec): 2189.7 MB/s
Did 339000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001090us (338630.9 ops/sec): 2774.1 MB/s
Did 173000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001056us (172817.5 ops/sec): 2831.4 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem_late_tag_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4724000 EVP-AES-128-GCM encrypt init operations in 1000069us (4723674.1 ops/sec)
Did 8029750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000023us (8029565.3 ops/sec): 128.5 MB/s
Did 4882000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000090us (4881560.7 ops/sec): 1249.7 MB/s
Did 1647000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000260us (1646571.9 ops/sec): 2222.9 MB/s
Did 347000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002344us (346188.5 ops/sec): 2836.0 MB/s
Did 177000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001567us (176723.1 ops/sec): 2895.4 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4725000 EVP-AES-128-GCM encrypt init operations in 1000185us (4724126.0 ops/sec)
Did 7968000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000114us (7967091.8 ops/sec): 127.5 MB/s
Did 4808500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000008us (4808461.5 ops/sec): 1231.0 MB/s
Did 1607000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000205us (1606670.6 ops/sec): 2169.0 MB/s
Did 333000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000417us (332861.2 ops/sec): 2726.8 MB/s
Did 170000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001197us (169796.8 ops/sec): 2782.0 MB/s
* Testing variant: opt/128_x4_scalar_iv_mem_late_tag_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4725000 EVP-AES-128-GCM encrypt init operations in 1000081us (4724617.3 ops/sec)
Did 8053000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000030us (8052758.4 ops/sec): 128.8 MB/s
Did 4810250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000006us (4810221.1 ops/sec): 1231.4 MB/s
Did 1644500 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000090us (1644352.0 ops/sec): 2219.9 MB/s
Did 346000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000311us (345892.4 ops/sec): 2833.6 MB/s
Did 177000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001877us (176668.4 ops/sec): 2894.5 MB/s
```

### SLOTHY (clean)

```
* Testing variant: clean/128_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4723000 EVP-AES-128-GCM encrypt init operations in 1000052us (4722754.4 ops/sec)
Did 8119000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000036us (8118707.7 ops/sec): 129.9 MB/s
Did 4094000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000108us (4093557.9 ops/sec): 1048.0 MB/s
Did 1187000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000091us (1186892.0 ops/sec): 1602.3 MB/s
Did 230000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001771us (229593.4 ops/sec): 1880.8 MB/s
Did 117000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002796us (116673.8 ops/sec): 1911.6 MB/s
* Testing variant: clean/128_x4_dual_acc
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4709000 EVP-AES-128-GCM encrypt init operations in 1000116us (4708453.8 ops/sec)
Did 8103500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000001us (8103491.9 ops/sec): 129.7 MB/s
Did 4165500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000020us (4165416.7 ops/sec): 1066.3 MB/s
Did 1204000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000087us (1203895.3 ops/sec): 1625.3 MB/s
Did 237000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1004016us (236052.0 ops/sec): 1933.7 MB/s
Did 120000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1005981us (119286.5 ops/sec): 1954.4 MB/s
* Testing variant: clean/128_x4_dual_acc_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4724000 EVP-AES-128-GCM encrypt init operations in 1000127us (4723400.1 ops/sec)
Did 8065000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000010us (8064919.4 ops/sec): 129.0 MB/s
Did 4125000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000215us (4124113.3 ops/sec): 1055.8 MB/s
Did 1197000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000545us (1196348.0 ops/sec): 1615.1 MB/s
Did 232000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000410us (231904.9 ops/sec): 1899.8 MB/s
Did 118000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006572us (117229.6 ops/sec): 1920.7 MB/s
* Testing variant: clean/128_x4_ilp
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4726000 EVP-AES-128-GCM encrypt init operations in 1000195us (4725078.6 ops/sec)
Did 7961750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000017us (7961614.7 ops/sec): 127.4 MB/s
Did 4325750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000032us (4325611.6 ops/sec): 1107.4 MB/s
Did 1320000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000007us (1319990.8 ops/sec): 1782.0 MB/s
Did 261000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001451us (260621.8 ops/sec): 2135.0 MB/s
Did 132000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1007071us (131073.2 ops/sec): 2147.5 MB/s
* Testing variant: clean/128_x4_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4725000 EVP-AES-128-GCM encrypt init operations in 1000032us (4724848.8 ops/sec)
Did 8042000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000020us (8041839.2 ops/sec): 128.7 MB/s
Did 4371000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000142us (4370379.4 ops/sec): 1118.8 MB/s
Did 1352000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000410us (1351445.9 ops/sec): 1824.5 MB/s
Did 266000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000237us (265937.0 ops/sec): 2178.6 MB/s
Did 135000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1000052us (134993.0 ops/sec): 2211.7 MB/s
* Testing variant: clean/128_x4_keep_htable_rotate
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4717000 EVP-AES-128-GCM encrypt init operations in 1000096us (4716547.2 ops/sec)
Did 7216500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000029us (7216290.7 ops/sec): 115.5 MB/s
Did 4092000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000182us (4091255.4 ops/sec): 1047.4 MB/s
Did 1314000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000348us (1313542.9 ops/sec): 1773.3 MB/s
Did 264000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002857us (263247.9 ops/sec): 2156.5 MB/s
Did 134000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1000009us (133998.8 ops/sec): 2195.4 MB/s
* Testing variant: clean/128_x4_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4721000 EVP-AES-128-GCM encrypt init operations in 1000207us (4720023.0 ops/sec)
Did 8113000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000112us (8112091.4 ops/sec): 129.8 MB/s
Did 4031000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000025us (4030899.2 ops/sec): 1031.9 MB/s
Did 1171000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000398us (1170534.1 ops/sec): 1580.2 MB/s
Did 226000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002185us (225507.3 ops/sec): 1847.4 MB/s
Did 115000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006855us (114217.0 ops/sec): 1871.3 MB/s
* Testing variant: clean/128_x4_reload_round_keys_full
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4705000 EVP-AES-128-GCM encrypt init operations in 1000036us (4704830.6 ops/sec)
Did 8188000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000092us (8187246.8 ops/sec): 131.0 MB/s
Did 4031250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000025us (4031149.2 ops/sec): 1032.0 MB/s
Did 1163000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000638us (1162258.5 ops/sec): 1569.0 MB/s
Did 223000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1003032us (222325.9 ops/sec): 1821.3 MB/s
Did 113000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003704us (112583.0 ops/sec): 1844.6 MB/s
* Testing variant: clean/128_x4_reload_round_keys_partial
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4710000 EVP-AES-128-GCM encrypt init operations in 1000049us (4709769.2 ops/sec)
Did 8194000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000077us (8193369.1 ops/sec): 131.1 MB/s
Did 4072500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000059us (4072259.7 ops/sec): 1042.5 MB/s
Did 1173000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000536us (1172371.6 ops/sec): 1582.7 MB/s
Did 227000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1004213us (226047.7 ops/sec): 1851.8 MB/s
Did 115000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1005911us (114324.2 ops/sec): 1873.1 MB/s
* Testing variant: clean/128_x4_scalar_iv
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4709000 EVP-AES-128-GCM encrypt init operations in 1000074us (4708651.6 ops/sec)
Did 8038250 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000031us (8038000.8 ops/sec): 128.6 MB/s
Did 3896000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000145us (3895435.2 ops/sec): 997.2 MB/s
Did 1092000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000776us (1091153.3 ops/sec): 1473.1 MB/s
Did 212000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1003974us (211160.8 ops/sec): 1729.8 MB/s
Did 107000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002490us (106734.2 ops/sec): 1748.7 MB/s
* Testing variant: clean/128_x4_scalar_iv2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4723000 EVP-AES-128-GCM encrypt init operations in 1000070us (4722669.4 ops/sec)
Did 8059000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000123us (8058008.9 ops/sec): 128.9 MB/s
Did 3896750 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000064us (3896500.6 ops/sec): 997.5 MB/s
Did 1094000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000781us (1093146.3 ops/sec): 1475.7 MB/s
Did 212000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1003473us (211266.3 ops/sec): 1730.7 MB/s
Did 107000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001199us (106871.9 ops/sec): 1751.0 MB/s
* Testing variant: clean/128_x4_scalar_iv2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4719000 EVP-AES-128-GCM encrypt init operations in 1000161us (4718240.4 ops/sec)
Did 8041750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000022us (8041573.1 ops/sec): 128.7 MB/s
Did 3851000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000034us (3850869.1 ops/sec): 985.8 MB/s
Did 1084000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000374us (1083594.7 ops/sec): 1462.9 MB/s
Did 209000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002928us (208389.8 ops/sec): 1707.1 MB/s
Did 106000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1007893us (105169.9 ops/sec): 1723.1 MB/s
* Testing variant: clean/128_x4_scalar_iv2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4728000 EVP-AES-128-GCM encrypt init operations in 1000139us (4727342.9 ops/sec)
Did 8015250 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000004us (8015217.9 ops/sec): 128.2 MB/s
Did 3856000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000030us (3855884.3 ops/sec): 987.1 MB/s
Did 1082000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000626us (1081323.1 ops/sec): 1459.8 MB/s
Did 209000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1003104us (208353.3 ops/sec): 1706.8 MB/s
Did 106000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006415us (105324.3 ops/sec): 1725.6 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4683000 EVP-AES-128-GCM encrypt init operations in 1000022us (4682897.0 ops/sec)
Did 7997000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000105us (7996160.4 ops/sec): 127.9 MB/s
Did 3893000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000106us (3892587.4 ops/sec): 996.5 MB/s
Did 1086000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000553us (1085399.8 ops/sec): 1465.3 MB/s
Did 208000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1004058us (207159.3 ops/sec): 1697.0 MB/s
Did 105000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1002900us (104696.4 ops/sec): 1715.3 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4727000 EVP-AES-128-GCM encrypt init operations in 1000056us (4726735.3 ops/sec)
Did 7457000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000061us (7456545.2 ops/sec): 119.3 MB/s
Did 2943000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000076us (2942776.3 ops/sec): 753.4 MB/s
Did 761000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000860us (760346.1 ops/sec): 1026.5 MB/s
Did 142000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000986us (141860.1 ops/sec): 1162.1 MB/s
Did 72000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1003065us (71780.0 ops/sec): 1176.0 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem2_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4727000 EVP-AES-128-GCM encrypt init operations in 1000204us (4726035.9 ops/sec)
Did 7390750 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000028us (7390543.1 ops/sec): 118.2 MB/s
Did 2887000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000243us (2886298.6 ops/sec): 738.9 MB/s
Did 744000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1001310us (743026.6 ops/sec): 1003.1 MB/s
Did 137000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000813us (136888.7 ops/sec): 1121.4 MB/s
Did 70000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1014129us (69024.7 ops/sec): 1130.9 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4722000 EVP-AES-128-GCM encrypt init operations in 1000114us (4721461.8 ops/sec)
Did 8035000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000038us (8034694.7 ops/sec): 128.6 MB/s
Did 3745500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000049us (3745316.5 ops/sec): 958.8 MB/s
Did 1024000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000754us (1023228.5 ops/sec): 1381.4 MB/s
Did 195000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1004482us (194129.9 ops/sec): 1590.3 MB/s
Did 99000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1008834us (98133.1 ops/sec): 1607.8 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem_late_tag_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4710000 EVP-AES-128-GCM encrypt init operations in 1000069us (4709675.0 ops/sec)
Did 8048000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000007us (8047943.7 ops/sec): 128.8 MB/s
Did 3763000 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000013us (3762951.1 ops/sec): 963.3 MB/s
Did 1034000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000425us (1033560.7 ops/sec): 1395.3 MB/s
Did 197000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1002139us (196579.5 ops/sec): 1610.4 MB/s
Did 100000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1006244us (99379.5 ops/sec): 1628.2 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem_late_tag_keep_htable_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4726000 EVP-AES-128-GCM encrypt init operations in 1000005us (4725976.4 ops/sec)
Did 8038500 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000004us (8038467.8 ops/sec): 128.6 MB/s
Did 3802250 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000005us (3802231.0 ops/sec): 973.4 MB/s
Did 1049000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000055us (1048942.3 ops/sec): 1416.1 MB/s
Did 200000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1001242us (199751.9 ops/sec): 1636.4 MB/s
Did 102000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1009127us (101077.5 ops/sec): 1656.1 MB/s
* Testing variant: clean/128_x4_scalar_iv_mem_late_tag_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4721000 EVP-AES-128-GCM encrypt init operations in 1000108us (4720490.2 ops/sec)
Did 8089000 EVP-AES-128-GCM encrypt (16 bytes) operations in 1000019us (8088846.3 ops/sec): 129.4 MB/s
Did 3872500 EVP-AES-128-GCM encrypt (256 bytes) operations in 1000047us (3872318.0 ops/sec): 991.3 MB/s
Did 1081000 EVP-AES-128-GCM encrypt (1350 bytes) operations in 1000478us (1080483.5 ops/sec): 1458.7 MB/s
Did 202000 EVP-AES-128-GCM encrypt (8192 bytes) operations in 1000267us (201946.1 ops/sec): 1654.3 MB/s
Did 105000 EVP-AES-128-GCM encrypt (16384 bytes) operations in 1001476us (104845.2 ops/sec): 1717.8 MB/s
```

## AES-128-GCM Decrypt

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
Did 4758250 EVP-AES-128-GCM decrypt init operations in 1000023us (4758140.6 ops/sec)
Did 7069750 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000030us (7069537.9 ops/sec): 113.1 MB/s
Did 4394000 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000123us (4393459.6 ops/sec): 1124.7 MB/s
Did 1439000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000099us (1438857.6 ops/sec): 1942.5 MB/s
Did 291000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1000594us (290827.2 ops/sec): 2382.5 MB/s
Did 149000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1005229us (148224.9 ops/sec): 2428.5 MB/s
```

### SLOTHY (optimized)

NOTE: The optimizations below were run with a low timeout of 30min per SLOTHY run. See the optimized
assembly files for the estimated optimal performance, and potentially re-run the optimizer with a
larger time budget.

```
* Testing variant: opt/dec/128_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4723500 EVP-AES-128-GCM decrypt init operations in 1000028us (4723367.7 ops/sec)
Did 7859750 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000021us (7859584.9 ops/sec): 125.8 MB/s
Did 4786250 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000009us (4786206.9 ops/sec): 1225.3 MB/s
Did 1580500 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000029us (1580454.2 ops/sec): 2133.6 MB/s
Did 328000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1001425us (327533.3 ops/sec): 2683.2 MB/s
Did 167000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1004095us (166318.9 ops/sec): 2725.0 MB/s

* Testing variant: opt/dec/128_x4_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4708750 EVP-AES-128-GCM decrypt init operations in 1000017us (4708670.0 ops/sec)
Did 7368750 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000017us (7368624.7 ops/sec): 117.9 MB/s
Did 4591000 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000175us (4590196.7 ops/sec): 1175.1 MB/s
Did 1592000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000187us (1591702.4 ops/sec): 2148.8 MB/s
Did 332000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1000610us (331797.6 ops/sec): 2718.1 MB/s
Did 170000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1000170us (169971.1 ops/sec): 2784.8 MB/s

* Testing variant: opt/dec/128_x4_scalar_iv_mem2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4710250 EVP-AES-128-GCM decrypt init operations in 1000042us (4710052.2 ops/sec)
Did 7329500 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000010us (7329426.7 ops/sec): 117.3 MB/s
Did 4525000 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000023us (4524895.9 ops/sec): 1158.4 MB/s
Did 1618000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000244us (1617605.3 ops/sec): 2183.8 MB/s
Did 343000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1001341us (342540.7 ops/sec): 2806.1 MB/s
Did 176000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1004341us (175239.3 ops/sec): 2871.1 MB/s

* Testing variant: opt/dec/128_x4_scalar_iv_mem_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4713750 EVP-AES-128-GCM decrypt init operations in 1000009us (4713707.6 ops/sec)
Did 7739000 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000023us (7738822.0 ops/sec): 123.8 MB/s
Did 4789000 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000007us (4788966.5 ops/sec): 1226.0 MB/s
Did 1646250 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000048us (1646171.0 ops/sec): 2222.3 MB/s
Did 345000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1002177us (344250.6 ops/sec): 2820.1 MB/s
Did 176000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1000969us (175829.6 ops/sec): 2880.8 MB/s

* Testing variant: opt/dec/128_x4_scalar_iv_mem_late_tag_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4718000 EVP-AES-128-GCM decrypt init operations in 1000164us (4717226.4 ops/sec)
Did 7737750 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000008us (7737688.1 ops/sec): 123.8 MB/s
Did 4753750 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000014us (4753683.4 ops/sec): 1216.9 MB/s
Did 1597000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000120us (1596808.4 ops/sec): 2155.7 MB/s
Did 330000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1000013us (329995.7 ops/sec): 2703.3 MB/s
Did 169000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1004000us (168326.7 ops/sec): 2757.9 MB/s
```

### SLOTHY (clean)

```
* Testing variant: clean/dec/128_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4676000 EVP-AES-128-GCM decrypt init operations in 1000172us (4675195.9 ops/sec)
Did 7819250 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000019us (7819101.4 ops/sec): 125.1 MB/s
Did 4292000 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000110us (4291527.9 ops/sec): 1098.6 MB/s
Did 1328000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000125us (1327834.0 ops/sec): 1792.6 MB/s
Did 264000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1000953us (263748.6 ops/sec): 2160.6 MB/s
Did 135000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1007009us (134060.4 ops/sec): 2196.4 MB/s

* Testing variant: clean/dec/128_x4_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4717500 EVP-AES-128-GCM decrypt init operations in 1000038us (4717320.7 ops/sec)
Did 7892000 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000023us (7891818.5 ops/sec): 126.3 MB/s
Did 4254500 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000055us (4254266.0 ops/sec): 1089.1 MB/s
Did 1311750 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000081us (1311643.8 ops/sec): 1770.7 MB/s
Did 259000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1001770us (258542.4 ops/sec): 2118.0 MB/s
Did 132000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1002755us (131637.3 ops/sec): 2156.7 MB/s

* Testing variant: clean/dec/128_x4_scalar_iv_mem2
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4683000 EVP-AES-128-GCM decrypt init operations in 1000053us (4682751.8 ops/sec)
Did 7331250 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000023us (7331081.4 ops/sec): 117.3 MB/s
Did 2840250 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000043us (2840127.9 ops/sec): 727.1 MB/s
Did 738000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000059us (737956.5 ops/sec): 996.2 MB/s
Did 135000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1002031us (134726.4 ops/sec): 1103.7 MB/s
Did 68000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1000915us (67937.8 ops/sec): 1113.1 MB/s

* Testing variant: clean/dec/128_x4_scalar_iv_mem_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4691000 EVP-AES-128-GCM decrypt init operations in 1000090us (4690577.8 ops/sec)
Did 7742750 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000022us (7742579.7 ops/sec): 123.9 MB/s
Did 4149750 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000011us (4149704.4 ops/sec): 1062.3 MB/s
Did 1252000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000493us (1251383.1 ops/sec): 1689.4 MB/s
Did 246000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1001144us (245718.9 ops/sec): 2012.9 MB/s
Did 125000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1002461us (124693.1 ops/sec): 2043.0 MB/s

* Testing variant: clean/dec/128_x4_scalar_iv_mem_late_tag_keep_htable
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4724000 EVP-AES-128-GCM decrypt init operations in 1000164us (4723225.4 ops/sec)
Did 7816250 EVP-AES-128-GCM decrypt (16 bytes) operations in 1000005us (7816210.9 ops/sec): 125.1 MB/s
Did 4177500 EVP-AES-128-GCM decrypt (256 bytes) operations in 1000024us (4177399.7 ops/sec): 1069.4 MB/s
Did 1254000 EVP-AES-128-GCM decrypt (1350 bytes) operations in 1000268us (1253664.0 ops/sec): 1692.4 MB/s
Did 246000 EVP-AES-128-GCM decrypt (8192 bytes) operations in 1000221us (245945.6 ops/sec): 2014.8 MB/s
Did 125000 EVP-AES-128-GCM decrypt (16384 bytes) operations in 1001957us (124755.9 ops/sec): 2044.0 MB/s
```

## AES-192-GCM Encrypt

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

* Testing variant: x4_scalar_iv_mem_late_tag_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4704000 EVP-AES-192-GCM encrypt init operations in 1000127us (4703402.7 ops/sec)
Did 7757250 EVP-AES-192-GCM encrypt (16 bytes) operations in 1000031us (7757009.5 ops/sec): 124.1 MB/s     + 7.8%
Did 4512750 EVP-AES-192-GCM encrypt (256 bytes) operations in 1000040us (4512569.5 ops/sec): 1155.2 MB/s   + 9.0%
Did 1468000 EVP-AES-192-GCM encrypt (1350 bytes) operations in 1000126us (1467815.1 ops/sec): 1981.6 MB/s  +15.6%
Did 303000 EVP-AES-192-GCM encrypt (8192 bytes) operations in 1000617us (302813.2 ops/sec): 2480.6 MB/s    +20.9%
Did 155000 EVP-AES-192-GCM encrypt (16384 bytes) operations in 1004542us (154299.2 ops/sec): 2528.0 MB/s   +21.4%

SLOTHY expectations:
// Instructions:    148
// Expected cycles: 62
// Expected IPC:    2.3870967741935485

SLOTHY expectation would correspond to:
- 64/62 * 2.5ghz = 2.58gb/s
```

## AES-192-GCM Decrypt

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
Did 4735000 EVP-AES-192-GCM decrypt init operations in 1000048us (4734772.7 ops/sec)
Did 6831250 EVP-AES-192-GCM decrypt (16 bytes) operations in 1000026us (6831072.4 ops/sec): 109.3 MB/s
Did 4160250 EVP-AES-192-GCM decrypt (256 bytes) operations in 1000067us (4159971.3 ops/sec): 1065.0 MB/s
Did 1330000 EVP-AES-192-GCM decrypt (1350 bytes) operations in 1000596us (1329207.8 ops/sec): 1794.4 MB/s
Did 267000 EVP-AES-192-GCM decrypt (8192 bytes) operations in 1001065us (266715.9 ops/sec): 2184.9 MB/s
Did 136000 EVP-AES-192-GCM decrypt (16384 bytes) operations in 1001676us (135772.4 ops/sec): 2224.5 MB/s
```

### SLOTHY (optimized)

```
* Testing variant: opt/dec/192_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4731000 EVP-AES-192-GCM decrypt init operations in 1000016us (4730924.3 ops/sec)
Did 7724000 EVP-AES-192-GCM decrypt (16 bytes) operations in 1000060us (7723536.6 ops/sec): 123.6 MB/s
Did 4515000 EVP-AES-192-GCM decrypt (256 bytes) operations in 1000217us (4514020.5 ops/sec): 1155.6 MB/s
Did 1460000 EVP-AES-192-GCM decrypt (1350 bytes) operations in 1000327us (1459522.7 ops/sec): 1970.4 MB/s
Did 296000 EVP-AES-192-GCM decrypt (8192 bytes) operations in 1000505us (295850.6 ops/sec): 2423.6 MB/s
Did 152000 EVP-AES-192-GCM decrypt (16384 bytes) operations in 1005236us (151208.3 ops/sec): 2477.4 MB/s

* Testing variant: opt/dec/192_x4_scalar_iv_mem2_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4665000 EVP-AES-192-GCM decrypt init operations in 1000004us (4664981.3 ops/sec)
Did 7198500 EVP-AES-192-GCM decrypt (16 bytes) operations in 1000022us (7198341.6 ops/sec): 115.2 MB/s
Did 4231250 EVP-AES-192-GCM decrypt (256 bytes) operations in 1000050us (4231038.4 ops/sec): 1083.1 MB/s
Did 1444000 EVP-AES-192-GCM decrypt (1350 bytes) operations in 1000206us (1443702.6 ops/sec): 1949.0 MB/s
Did 299000 EVP-AES-192-GCM decrypt (8192 bytes) operations in 1000522us (298844.0 ops/sec): 2448.1 MB/s
Did 153000 EVP-AES-192-GCM decrypt (16384 bytes) operations in 1003000us (152542.4 ops/sec): 2499.3 MB/s
```

### SLOTHY (clean)

```
 Testing variant: clean/dec/192_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4666750 EVP-AES-192-GCM decrypt init operations in 1000022us (4666647.3 ops/sec)
Did 7676250 EVP-AES-192-GCM decrypt (16 bytes) operations in 1000030us (7676019.7 ops/sec): 122.8 MB/s
Did 3957500 EVP-AES-192-GCM decrypt (256 bytes) operations in 1000038us (3957349.6 ops/sec): 1013.1 MB/s
Did 1177000 EVP-AES-192-GCM decrypt (1350 bytes) operations in 1000699us (1176177.9 ops/sec): 1587.8 MB/s
Did 229000 EVP-AES-192-GCM decrypt (8192 bytes) operations in 1003455us (228211.5 ops/sec): 1869.5 MB/s
Did 116000 EVP-AES-192-GCM decrypt (16384 bytes) operations in 1002142us (115752.1 ops/sec): 1896.5 MB/s

* Testing variant: clean/dec/192_x4_scalar_iv_mem2_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4721250 EVP-AES-192-GCM decrypt init operations in 1000012us (4721193.3 ops/sec)
Did 7255750 EVP-AES-192-GCM decrypt (16 bytes) operations in 1000014us (7255648.4 ops/sec): 116.1 MB/s
Did 2636000 EVP-AES-192-GCM decrypt (256 bytes) operations in 1000050us (2635868.2 ops/sec): 674.8 MB/s
Did 667000 EVP-AES-192-GCM decrypt (1350 bytes) operations in 1001004us (666331.0 ops/sec): 899.5 MB/s
Did 120000 EVP-AES-192-GCM decrypt (8192 bytes) operations in 1000746us (119910.5 ops/sec): 982.3 MB/s
Did 61000 EVP-AES-192-GCM decrypt (16384 bytes) operations in 1010052us (60392.9 ops/sec): 989.5 MB/s
```

## AES-256-GCM Encrypt

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

* Testing variant: x4_scalar_iv_mem_late_tag_scalar_rk
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4537000 EVP-AES-256-GCM encrypt init operations in 1000068us (4536691.5 ops/sec)
Did 7576750 EVP-AES-256-GCM encrypt (16 bytes) operations in 1000016us (7576628.8 ops/sec): 121.2 MB/s        + 9.0%
Did 4245000 EVP-AES-256-GCM encrypt (256 bytes) operations in 1000003us (4244987.3 ops/sec): 1086.7 MB/s      + 8.1%
Did 1330000 EVP-AES-256-GCM encrypt (1350 bytes) operations in 1000440us (1329415.1 ops/sec): 1794.7 MB/s     +13.8%
Did 270000 EVP-AES-256-GCM encrypt (8192 bytes) operations in 1003190us (269141.4 ops/sec): 2204.8 MB/s       +18.5%
Did 137000 EVP-AES-256-GCM encrypt (16384 bytes) operations in 1000652us (136910.7 ops/sec): 2243.1 MB/s      +18.9%

SLOTHY expectations:
// Instructions:    156
// Expected cycles: 70
// Expected IPC:    2.2285714285714286

SLOTHY expectations would correspond to:
- 64/70 * 2.5ghz = 2.28gb/s

```

## AES-256-GCM Decrypt

### AWS-LC (5ede432e141172df7ac847b68c40837b7349f1f3)

```
Did 4578250 EVP-AES-256-GCM decrypt init operations in 1000007us (4578218.0 ops/sec)
Did 6597500 EVP-AES-256-GCM decrypt (16 bytes) operations in 1000010us (6597434.0 ops/sec): 105.6 MB/s
Did 3917000 EVP-AES-256-GCM decrypt (256 bytes) operations in 1000040us (3916843.3 ops/sec): 1002.7 MB/s
Did 1216000 EVP-AES-256-GCM decrypt (1350 bytes) operations in 1000043us (1215947.7 ops/sec): 1641.5 MB/s
Did 241000 EVP-AES-256-GCM decrypt (8192 bytes) operations in 1002470us (240406.2 ops/sec): 1969.4 MB/s
Did 123000 EVP-AES-256-GCM decrypt (16384 bytes) operations in 1006915us (122155.3 ops/sec): 2001.4 MB/s
```

### SLOTHY (optimized)

```
* Testing variant: opt/dec/256_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4532000 EVP-AES-256-GCM decrypt init operations in 1000140us (4531365.6 ops/sec)
Did 7491000 EVP-AES-256-GCM decrypt (16 bytes) operations in 1000025us (7490812.7 ops/sec): 119.9 MB/s
Did 4183000 EVP-AES-256-GCM decrypt (256 bytes) operations in 1000052us (4182782.5 ops/sec): 1070.8 MB/s
Did 1327000 EVP-AES-256-GCM decrypt (1350 bytes) operations in 1000075us (1326900.5 ops/sec): 1791.3 MB/s
Did 268000 EVP-AES-256-GCM decrypt (8192 bytes) operations in 1001194us (267680.4 ops/sec): 2192.8 MB/s
Did 137000 EVP-AES-256-GCM decrypt (16384 bytes) operations in 1005918us (136194.0 ops/sec): 2231.4 MB/s

* Testing variant: opt/dec/256_x4_scalar_iv_mem2_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4520000 EVP-AES-256-GCM decrypt init operations in 1000065us (4519706.2 ops/sec)
Did 6948000 EVP-AES-256-GCM decrypt (16 bytes) operations in 1000003us (6947979.2 ops/sec): 111.2 MB/s
Did 3968750 EVP-AES-256-GCM decrypt (256 bytes) operations in 1000058us (3968519.8 ops/sec): 1015.9 MB/s
Did 1298000 EVP-AES-256-GCM decrypt (1350 bytes) operations in 1000158us (1297794.9 ops/sec): 1752.0 MB/s
Did 264000 EVP-AES-256-GCM decrypt (8192 bytes) operations in 1000620us (263836.4 ops/sec): 2161.3 MB/s
Did 135000 EVP-AES-256-GCM decrypt (16384 bytes) operations in 1004311us (134420.5 ops/sec): 2202.3 MB/s
```

### SLOTHY (clean)

```
* Testing variant: clean/dec/256_x4_basic
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4573000 EVP-AES-256-GCM decrypt init operations in 1000181us (4572172.4 ops/sec)
Did 7457000 EVP-AES-256-GCM decrypt (16 bytes) operations in 1000024us (7456821.0 ops/sec): 119.3 MB/s
Did 3688000 EVP-AES-256-GCM decrypt (256 bytes) operations in 1000164us (3687395.3 ops/sec): 944.0 MB/s
Did 1075000 EVP-AES-256-GCM decrypt (1350 bytes) operations in 1000304us (1074673.3 ops/sec): 1450.8 MB/s
Did 207000 EVP-AES-256-GCM decrypt (8192 bytes) operations in 1003258us (206327.8 ops/sec): 1690.2 MB/s
Did 105000 EVP-AES-256-GCM decrypt (16384 bytes) operations in 1005955us (104378.4 ops/sec): 1710.1 MB/s

* Testing variant: clean/dec/256_x4_scalar_iv_mem2_late_tag
 - Copy... OK!
 - Build... OK!
 - Test... OK!
 - Bench...
Did 4549000 EVP-AES-256-GCM decrypt init operations in 1000132us (4548399.6 ops/sec)
Did 6956250 EVP-AES-256-GCM decrypt (16 bytes) operations in 1000014us (6956152.6 ops/sec): 111.3 MB/s
Did 2451000 EVP-AES-256-GCM decrypt (256 bytes) operations in 1000084us (2450794.1 ops/sec): 627.4 MB/s
Did 613000 EVP-AES-256-GCM decrypt (1350 bytes) operations in 1000741us (612546.1 ops/sec): 826.9 MB/s
Did 110000 EVP-AES-256-GCM decrypt (8192 bytes) operations in 1004162us (109544.1 ops/sec): 897.4 MB/s
Did 56000 EVP-AES-256-GCM decrypt (16384 bytes) operations in 1008177us (55545.8 ops/sec): 910.1 MB/s
```
