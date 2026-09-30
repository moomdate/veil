# การออก Release

[English](releasing.md)

## ตั้งค่าครั้งเดียว

1. เปิด `moomdate/veil` เป็น public เพราะ Homebrew ดาวน์โหลดจาก repo private ไม่ได้
2. สร้าง repo tap (public และว่างเปล่า):
   ```sh
   gh repo create moomdate/homebrew-tap --public --description "Homebrew tap for Veil"
   ```
3. สร้าง fine-grained token ที่ GitHub → Settings → Developer settings →
   Fine-grained tokens ให้เข้าถึงเฉพาะ repo `moomdate/homebrew-tap`
   และให้สิทธิ์แค่ Contents แบบ read and write เท่านั้น
4. เก็บ token เป็น Actions secret ชื่อ `HOMEBREW_TAP_TOKEN` ใน repo Veil:
   ```sh
   gh secret set HOMEBREW_TAP_TOKEN --repo moomdate/veil
   ```
   วาง token ตอนที่ระบบถาม token จะได้ไม่ไปอยู่ใน shell history

## ทุกครั้งที่ออก release

1. อัปเดต `CHANGELOG.md` โดยย้ายหัวข้อ "Unreleased" ไปไว้ใต้เวอร์ชันใหม่
2. ลองรัน pipeline ในเครื่องก่อน:
   ```sh
   go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,sbom,publish
   ```
3. ติด tag แล้ว push:
   ```sh
   git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0
   ```

จากนั้น release workflow จะรันเทส build binary ที่ sign แล้วสำหรับ macOS
และ Linux พร้อม checksum, SBOM และลายเซ็น cosign สร้าง GitHub release
และส่งสูตร Homebrew ขึ้น tap ให้เอง ผู้ใช้ติดตั้งได้ด้วย:

```sh
brew install moomdate/tap/veil
```

## สูตร Homebrew ทำงานอย่างไร

`packaging/homebrew/veil.rb.tmpl` build Veil จาก source ที่ติด tag, sign
ด้วย hardened runtime และติดตั้ง shell completion ให้ ทุกครั้งที่ติด tag
`packaging/homebrew/update-tap.sh` จะใส่ URL และ sha256 ของ tarball แล้ว
push `Formula/veil.rb` ขึ้น tap ถ้ายังไม่ได้ตั้ง `HOMEBREW_TAP_TOKEN`
ขั้นตอนนี้จะถูกข้ามไป

ทดสอบการแก้สูตรก่อนออก release ได้ด้วยการติดตั้งจาก tap ในเครื่อง:

```sh
git archive --format=tar.gz --prefix=veil-0.0.0/ -o /tmp/veil-0.0.0.tar.gz HEAD
brew tap-new --no-git veiltest/local
packaging/homebrew/render.sh 0.0.0 file:///tmp/veil-0.0.0.tar.gz \
  "$(shasum -a 256 /tmp/veil-0.0.0.tar.gz | cut -d' ' -f1)" \
  > "$(brew --repository veiltest/local)/Formula/veil.rb"
brew install --build-from-source veiltest/local/veil && brew test veiltest/local/veil
brew uninstall veil && brew untap veiltest/local
```
