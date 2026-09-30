# สถาปัตยกรรม

[English](architecture.md)

Veil เป็น Go binary ไฟล์เดียว ทำหน้าที่เป็น CLI และหน้าเว็บบนเครื่องสำหรับคุณ และเป็น MCP server
สำหรับ agent ทั้งสามทางวิ่งผ่าน broker ตัวเดียวกัน กฎจึงไม่มีทางต่างกันไม่ว่าใครจะเป็นคนขอ

```text
 you ──► veil CLI ─────┐
 you ──► veil ui ──────┤  (web; reveal and loosening need Touch ID via presence)
                       ▼
 agent ─► veil mcp ──► broker ──► policy ──► runner ──────► child process
         (stdio)        │   │                 httpinject ──► HTTPS API
                        │   └──► redact (every output passes through)
                        ├──► vault ◄── keystore (OS keychain)
                        └──► audit log
```

## Packages

โค้ดทั้งหมดอยู่ใน `internal/` จึงยังไม่มีส่วนไหนเป็น Go API สาธารณะ

| Package | หน้าที่ | เห็นค่าจริงไหม |
|---|---|---|
| `secret` | `Secret`, `Tier` และ `Value` ซึ่งเป็น type ที่ถูกพิมพ์หรือ serialize ออกไปโดยไม่ตั้งใจไม่ได้ | ถือค่าไว้ |
| `keystore` | โหลดและบันทึก master key ขนาด 32 byte บน macOS (cgo) เป็นรายการใน Keychain ที่เชื่อใจเฉพาะ binary ของ Veil และจะไม่ทำงานจาก binary ที่ไม่มี hardened runtime บนระบบอื่นใช้ Secret Service ส่วน `Memory` มีไว้ใช้ในเทส | เห็นเฉพาะ key |
| `presence` | ขอให้คนที่อยู่หน้าเครื่องยืนยันด้วย Touch ID หรือรหัสผ่าน ผ่าน LocalAuthentication ภายใน process ของ Veil เอง ส่วน `Fake` มีไว้ใช้ในเทส | ไม่ |
| `dotenv` | parse ไฟล์ `.env` สำหรับการ import | ไม่ |
| `vault` | ไฟล์ที่เข้ารหัสเป็น blob XChaCha20-Poly1305 ก้อนเดียว เขียนแบบ atomic สิทธิ์ `0600` | ใช่ เพื่อเข้ารหัส |
| `policy` | pure function ที่ตัดสินว่า secret นี้ไปที่ host นี้ได้ไหม ใส่ในคำสั่งนี้ได้ไหม ใส่ในส่วนนี้ของ request ได้ไหม | ไม่ |
| `redact` | แทนค่าจริงและ encoding ต่าง ๆ ด้วย `[HIDDEN:NAME]` ได้ทั้งแบบ batch และ streaming | ใช่ เพื่อจับคู่ |
| `runner` | รันคำสั่งโดยใส่ secret ใน environment เก็บ output ผ่าน redactor และบังคับ timeout กับทั้ง process group | ใช่ เพื่อใส่ค่า |
| `httpinject` | เติม placeholder `{{secret:NAME}}` หลังตรวจ host และตำแหน่งที่ใส่แล้ว ไม่ follow redirect และ redact response | ใช่ เพื่อใส่ค่า |
| `audit` | log แบบ JSON Lines ที่เขียนต่อท้ายอย่างเดียว เก็บแค่ชื่อ | ไม่ |
| `broker` | เปิด vault ใช้ policy เรียก runner หรือ httpinject และบันทึก audit event | ไม่ (แค่ส่ง `Value` ต่อ) |
| `mcpserver` | MCP tool 3 ตัวที่อยู่บน broker | ไม่ |
| `web` | `veil ui`: template, CSS และ script เล็ก ๆ ที่ฝังไว้ใน binary มี session, CSRF, ตรวจ Host และ CSP แบบเข้มงวด | ใช่ เพื่อแสดงค่าหลัง `presence` ยืนยันแล้ว |
| `cli` | คำสั่ง Cobra และ UI บน terminal | ไม่ |

"เห็นค่าจริง" หมายถึง package นั้นเรียก `Value.Reveal()` มี lint rule คอยกันไม่ให้รายการนี้
ยาวขึ้นโดยไม่มีใครสังเกต

## เส้นทางของ request หนึ่งครั้ง

agent เรียก `http_request` พร้อม `Authorization: Bearer {{secret:STRIPE_KEY}}`
และ `https://api.stripe.com/v1/charges`

1. `mcpserver` ตรวจ input เทียบกับ JSON schema ของ tool แล้วเรียก `broker.HTTP`
   พร้อมชื่อ agent ที่ได้จาก MCP client info
2. `broker` เปิด vault โดยอ่านไฟล์ใหม่ทุกครั้ง การเปลี่ยนแปลงที่ทำผ่าน CLI จึงมีผลทันที
   แล้วสร้าง redactor จาก secret ทุกตัว
3. `httpinject` parse URL ปฏิเสธ placeholder ที่อยู่ใน host หรือในชื่อ header จากนั้น
   ตรวจ secret ที่ถูกอ้างถึงทุกตัวด้วย `policy.CheckHTTP` (tier, `https`, host ที่อนุญาต)
   และ `policy.CheckPlacement` (header, URL หรือ body)
4. หลังจากนั้นเท่านั้นจึงเติมค่าจริงและส่ง request โดยปิดการ follow redirect
5. body และ header ของ response ผ่าน redactor ส่วน error จากชั้น transport ซึ่งอาจยก
   URL มาอ้าง ก็ถูก redact ด้วย
6. `broker` เขียน audit event หนึ่งรายการ (`used`, `denied` หรือ `failed`) แล้วคืน
   response ที่ redact แล้ว

## รูปแบบไฟล์ vault

```json
{"format": "veil-vault", "version": 1, "nonce": "<24 bytes, base64>", "ciphertext": "<base64>"}
```

plaintext คือ JSON array ของ secret พร้อมค่าจริง associated data คือ `veil-vault:v1`
ดังนั้นถ้าแก้ฟิลด์ version การถอดรหัสจะล้มเหลว ทุกครั้งที่บันทึกจะใช้ nonce สุ่มใหม่
และแทนที่ไฟล์ด้วยการ rename แบบ atomic

## การทดสอบ

| ชั้น | อยู่ที่ไหน |
|---|---|
| Unit test | อยู่ข้าง ๆ แต่ละ package |
| Fuzzing | `internal/redact`: ค่าต้องไม่หลุดไม่ว่าค่า ข้อความรอบข้าง หรือ encoding จะเป็นอะไร และ output แบบ streaming ต้องเท่ากับแบบ batch ทุกขนาด chunk |
| Canary end-to-end | `test/e2e`: MCP client จริงลองดึงค่าออกหลายรูปแบบ แล้วค้นหา canary ทุกตัวในทุก encoding ใน transcript, audit log และไฟล์ vault |
| CLI | `internal/cli`: รันคำสั่งโดยใช้ keystore ในหน่วยความจำ |
| Web UI | `internal/web`: HTTP server จริง ทดสอบ Host ผิด ไม่มี session ลิงก์ที่ใช้ซ้ำ ไม่มี CSRF request ข้าม origin การแสดงค่าและการผ่อนกฎโดยไม่ผ่าน presence ชื่อที่ไม่ถูกต้อง และยืนยันว่าไม่มีหน้าไหนมีค่าจริงอยู่เลย |

รัน `make check` ก่อนส่ง pull request
