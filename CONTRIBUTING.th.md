# ร่วมพัฒนา Veil

[English](CONTRIBUTING.md)

ขอบคุณที่มาช่วยกัน Veil เป็นซอฟต์แวร์ด้านความปลอดภัยที่ผู้ใช้มักรีบใช้งาน เราจึงให้ความสำคัญ
กับ **ความปลอดภัย** และ **ความง่ายในการใช้งาน** เท่า ๆ กัน

## เตรียมเครื่อง

ต้องใช้ Go 1.26 ขึ้นไป

```sh
git clone https://github.com/moomdate/veil && cd veil
make test      # unit, CLI and canary end-to-end tests with the race detector
make lint      # golangci-lint and govulncheck
make fuzz      # fuzz the redactor for a minute
make build     # ./bin/veil
```

ถ้าจะลองใช้ build ของตัวเองโดยไม่แตะ vault จริง ให้ชี้ไปที่ directory ทดลอง:
`VEIL_HOME=/tmp/veil-dev ./bin/veil init` บน macOS `make build` จะ sign binary ด้วย
hardened runtime ให้ ส่วน binary จาก `go build` ธรรมดาจะ sign ตัวเองตอนรันครั้งแรก

web UI อยู่ใน `internal/web`: Go template, ไฟล์ CSS หนึ่งไฟล์ และ script เล็ก ๆ หนึ่งไฟล์
ทั้งหมดฝังอยู่ใน binary ไม่มี Node toolchain หน้าเว็บต้องใช้งานได้แม้ไม่มี script และห้ามโหลด
อะไรจาก origin อื่นเด็ดขาด (CSP ไม่อนุญาต)

## โครงสร้างของโค้ด

อ่าน [docs/architecture.th.md](docs/architecture.th.md) ก่อน สรุปสั้น ๆ คือทุก operation
วิ่งผ่าน `internal/broker` ซึ่งใช้ `internal/policy` ทำงานตามที่ขอ redact output
และเขียน audit log

## กฎสำหรับการเปลี่ยนแปลงที่กระทบความปลอดภัย

- เฉพาะ `vault`, `redact`, `runner`, `httpinject` และ `web` (หลังยืนยันด้วย Touch ID)
  เท่านั้นที่เรียก `secret.Value.Reveal()` ได้ linter บังคับไว้ ถ้าคิดว่า package อื่นจำเป็นต้องใช้
  ให้เปิด issue คุยกันก่อน
- อะไรก็ตามที่ส่งข้อมูลกลับไปหา agent ต้องผ่าน broker และ redactor
- การเพิ่ม MCP tool หรือวิธีใหม่ในการใส่ secret ต้องมี canary test ใน `test/e2e`
  ที่พยายามดึงค่าออกผ่านช่องทางนั้น
- ถ้าเปลี่ยนสิ่งที่ Veil ป้องกันได้ ให้อัปเดต [docs/threat-model.th.md](docs/threat-model.th.md)
  ใน pull request เดียวกัน

## สไตล์การเขียนสำหรับทุกอย่างที่ผู้ใช้อ่าน

output ของ CLI, error และเอกสาร ใช้กฎเดียวกับ UI:

- ใช้คำที่คนทั่วไปรู้จัก: "allowed hosts" ไม่ใช่ "domain allowlist" และ "hidden"
  ไม่ใช่ "redacted"
- error ต้องบอกว่าเกิดอะไรผิดพลาดและต้องทำอะไรต่อ เช่น
  "no vault yet. Run `veil init` to create one."
- ห้ามพิมพ์ค่า secret ออกมา รวมถึงใน error และ debug output
- เอกสารมีทั้งภาษาอังกฤษและภาษาไทย (`*.th.md`) ถ้าแก้ฉบับหนึ่ง ให้แก้อีกฉบับด้วย
  หรือระบุใน pull request ว่ายังต้องแปล

## สไตล์โค้ด

- package เล็ก ๆ ที่ทำหน้าที่เดียว ส่ง dependency เข้ามา (ไม่ใช้ global) เพื่อให้ทดสอบ
  ทุกอย่างได้โดยไม่ต้องใช้ keychain หรือ network จริง
- comment อธิบายว่า *ทำไม* โดยเฉพาะตรงที่เป็นการตัดสินใจด้านความปลอดภัย
- เทสเขียนแบบ table-driven ในจุดที่ช่วยได้ และตั้งชื่อตามการโจมตีที่มันกันไว้
- commit message ใช้ [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `sec:`, `docs:`) ซึ่งใช้สร้าง changelog

## การออก Release

ดู [docs/releasing.th.md](docs/releasing.th.md)

## Pull request

ทำให้กระชับและมีเรื่องเดียว กรอก checklist ใน template ให้ครบ CI จะรันเทสบน Linux
และ macOS, linter, govulncheck, CodeQL และ fuzz รอบสั้น
