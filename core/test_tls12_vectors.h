/* OpenSSL 3.6.5 TLS1-PRF fixtures. Inputs: shared=00..1f, cr=20..3f,
 * sr=60..7f, handshake transcript=00..7e (127 bytes).
 * kdf -binary -keylen N -kdfopt digest:SHA384 (or SHA256)
 * -kdfopt hexsecret:HEX -kdfopt hexseed:HEX(label || seed) TLS1-PRF.
 * master seed=cr||sr, expansion seed=sr||cr, EMS/Finished seed=Hash(transcript).
 * Generator and exact commands retained in results/19-evidence/generate-vectors.py. */
static const struct { uint16_t id; int ems; const char *master, *kb, *finished; } schedules[] = {
    {0xc02f,0,
      "6def5da66bba4f0f4032c970de9173a35191949da939a20444e2aeb508505e432b49e43b731339a8278f03d259726254",
      "e9192e3f94f9c07d2a45953f31203ea7cde60b635aa7d28acb9c873a8b86c1413b8da243acc1f915",
      "5c9ec09fe42fa7a7e022ba08"},
    {0xc02f,1,
      "44c23160e9cdb9702f8b47a364cfb1b76ea11bfad664562564683a84b585c692f0bb5052aa99fac060c8178b447829fd",
      "a12aac0e72eae19538f22722c570cc2462cb05860073e60f7238eb9f45ea0c5f9afdb333d8318858",
      "2ffa2c1b2c1ab7b429887710"},
    {0xc030,0,
      "97e09372d915c02ddaf516146b7e3056149dac009fe12f382baa38ce6011b7e5cae00b3cdf5c97ce0d7726c0575e437f",
      "4ccf8eb20977c8450e4e046839294ce90f0adb987e1bf3149bc8b58c5de47cf558a3dc2b7b27c2dc73d744eba5f72f8c4ac4d750552dea00715f7070c65e53f26bbaab749d489d49",
      "8ced082b23530f736d1b11b2"},
    {0xc030,1,
      "0ee31cb46587a00ccff941bd5ecc0701167eafae19424cf3c8a5fe274bb391934f3a41f4d3914ae290faa386bf420184",
      "d47b0d3221ce537ef4d9a4beb451d3d88499ba0b31774ef38d9984b29585a771dda65c4769385be3eec8d5ccc95da9f4bbfd821c67c9c79f8036db0cdf8af5ac1c2bcdb95753fbac",
      "51d360da3bbd1f075c8678fd"},
    {0xcca8,0,
      "6def5da66bba4f0f4032c970de9173a35191949da939a20444e2aeb508505e432b49e43b731339a8278f03d259726254",
      "e9192e3f94f9c07d2a45953f31203ea7cde60b635aa7d28acb9c873a8b86c1413b8da243acc1f91589a023b7e0f9f3a348a94168e934dac2704b47f82747be5a913d0d384e029769af335860ebd30a2d8496abf48956e95b",
      "5c9ec09fe42fa7a7e022ba08"},
    {0xcca8,1,
      "44c23160e9cdb9702f8b47a364cfb1b76ea11bfad664562564683a84b585c692f0bb5052aa99fac060c8178b447829fd",
      "a12aac0e72eae19538f22722c570cc2462cb05860073e60f7238eb9f45ea0c5f9afdb333d8318858abf928a481522953ed8d6d219054f895a266215736e038f1808cb16b487431043075133a46d0e3bc1de2fd1165ebc553",
      "2ffa2c1b2c1ab7b429887710"},
};
