# InjecAsst

InjecAsst, web uygulamalarının güvenlik mekanizmalarını analiz etmek ve yetkili güvenlik testleri gerçekleştirmek amacıyla geliştirilmiş, Python tabanlı modüler bir komut satırı (CLI) aracıdır.

Proje; web uygulaması güvenliği, penetrasyon testi, güvenlik araştırmaları ve kontrollü laboratuvar çalışmaları için tasarlanmıştır. Her araç belirli bir analiz görevine odaklanır ve ortak CLI arayüzü üzerinden çalıştırılır.

## Özellikler

* Login Analyzer
* Endpoint Mapper
* Parameter Mapper
* Database Printer
* Extractor
* Resource Scanner
* WAF Bypass Analysis
* Modüler CLI mimarisi
* Tool bazlı çalışma yapısı
* Terminal tabanlı kullanım
* Genişletilebilir araç mimarisi

## Proje Yapısı

```text
Injecasst/
├── cli/
│   ├── main.py
│   └── tools/
│       ├── loginAnalyzer.py
│       ├── endpointMapper.py
│       ├── parameterMapper.py
│       ├── dbprint.py
│       ├── extractor.py
│       ├── rescom.py
│       └── wafbypass.py
├── LICENSE
├── RAEDME.md
└── pyproject.toml
```

## Gereksinimler

* Python 3.x
* Git
* pip
* İnternet bağlantısı

Python sürümünüzü kontrol etmek için:

```bash
python3 --version
```

## Kurulum

### 1. Repository'yi klonlayın

```bash
git clone https://github.com/betulakmercann/Injecasst.git
cd Injecasst
```

### 2. Sanal ortam oluşturun

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. InjecAsst'i kurun

Proje ana dizinindeyken:

```bash
python -m pip install .
```

Kurulum tamamlandığında `cast` komutu kullanılabilir hale gelir.

### 4. InjecAsst'i başlatın

```bash
cast
```

`cast` komutu InjecAsst'in ana CLI arayüzünü başlatır.

## Kullanım

InjecAsst başlatıldığında mevcut araçlar ana CLI üzerinden kullanıcıya sunulur.

Genel çalışma akışı:

1. `cast` komutu çalıştırılır.
2. InjecAsst ana CLI arayüzü açılır.
3. Kullanılacak tool seçilir.
4. Tool tarafından istenen hedef bilgileri girilir.
5. Analiz gerçekleştirilir.
6. Sonuçlar terminal üzerinde görüntülenir.
7. Kullanıcı ana menüye dönebilir veya işlemini sonlandırabilir.





## Tools

### Login Analyzer

Login Analyzer, web uygulamalarındaki login mekanizmalarını analiz etmek ve güvenlik açısından incelenebilecek noktaları belirlemek amacıyla geliştirilmiştir.

Tool tarafından istenen hedef bilgileri girildikten sonra analiz gerçekleştirilir ve sonuçlar terminal üzerinde görüntülenir.

Örnek hedef:

```text
https://example.com/login
```

### Endpoint Mapper

Endpoint Mapper, hedef web uygulamasında bulunan endpoint'leri tespit etmek ve haritalamak amacıyla geliştirilmiştir.

Elde edilen endpoint bilgileri güvenlik testlerinin sonraki aşamalarında kullanılabilecek şekilde terminal üzerinde görüntülenir.

### Parameter Mapper

Parameter Mapper, web uygulamalarında kullanılan parametreleri tespit etmek ve analiz etmek amacıyla geliştirilmiştir.

Tespit edilen parametreler, yetkili güvenlik testlerinde incelenebilecek giriş noktalarının belirlenmesine yardımcı olur.

### Database Printer

Database Printer, güvenlik testleri sırasında elde edilen veritabanı bilgilerini yapılandırılmış şekilde görüntülemek amacıyla geliştirilmiştir.

### Extractor

Extractor, yetkili güvenlik testleri sırasında elde edilen verilerin analiz edilmesi ve ilgili sonuçların yapılandırılmış şekilde görüntülenmesine yardımcı olur.

### Resource Scanner

Resource Scanner, hedef web uygulamasında bulunan veya erişilebilir durumdaki kaynakların incelenmesine yardımcı olur.

### WAF Bypass Analysis

WAF Bypass Analysis, web uygulamalarında kullanılan Web Application Firewall mekanizmalarının güvenlik testleri kapsamında değerlendirilmesine yardımcı olur.

Bu özellik yalnızca yetkili ve kontrollü güvenlik testlerinde kullanılmalıdır.

## Açık Kaynak

InjecAsst açık kaynak olarak geliştirilmektedir.

Kaynak kodu inceleyebilir, projeyi kendi ortamınızda çalıştırabilir, hata bildirebilir ve lisans koşullarına uygun şekilde projeye katkıda bulunabilirsiniz.

Projeyi klonlamak için:

```bash
git clone https://github.com/betulakmercann/Injecasst.git
```

### Resmi Repository

InjecAsst'in resmi repository'si:

```text
https://github.com/betulakmercann/Injecasst
```

GitHub üzerindeki fork'lar, türetilmiş çalışmalar ve üçüncü taraf değişiklikler resmi InjecAsst sürümü olarak kabul edilmez.


## Katkıda Bulunma

InjecAsst açık kaynak bir proje olduğu için geliştiriciler projeye katkıda bulunabilir, hata düzeltebilir, yeni özellikler geliştirebilir veya mevcut araçları iyileştirebilir.

Katkıda bulunmak için aşağıdaki adımları izleyin.

### 1. Repository'yi Fork Edin

Öncelikle InjecAsst'in GitHub repository'sine gidin:

```text
https://github.com/betulakmercann/Injecasst
```

GitHub sayfasında sağ üst bölümde bulunan **Fork** butonuna tıklayın.

GitHub sizden fork'un oluşturulacağı hesabı seçmenizi isteyebilir. Kendi hesabınızı seçerek devam edin.

Bunun sonucunda InjecAsst repository'sinin kendi GitHub hesabınızdaki bağımsız bir kopyası oluşturulur.

Örneğin:

```text
Resmi repository:
https://github.com/betulakmercann/Injecasst

Sizin fork'unuz:
https://github.com/YOUR-USERNAME/Injecasst
```

Fork'unuz üzerinde yaptığınız değişiklikler resmi repository'yi doğrudan değiştirmez.

### 2. Fork'unuzu Bilgisayarınıza Klonlayın

Fork oluşturduktan sonra kendi repository'nizin sayfasına gidin.

**Code → HTTPS → Copy** seçeneğini kullanarak repository adresini kopyalayın.

Ardından terminalde:

```bash
git clone https://github.com/YOUR-USERNAME/Injecasst.git
cd Injecasst
```

### 3. Yeni Bir Branch Oluşturun

Değişiklikleri doğrudan `main` branch'i üzerinde yapmak yerine yeni bir branch oluşturmanız önerilir:

```bash
git checkout -b feature/new-feature
```

Örneğin:

```bash
git checkout -b fix/login-analyzer
```

### 4. Değişikliklerinizi Yapın

Projeyi geliştirin, hata düzeltin veya yeni bir özellik ekleyin.

Değişikliklerden sonra projenin çalıştığından emin olun.

Git ile yapılan değişiklikleri kontrol etmek için:

```bash
git status
```

Değişiklikleri görmek için:

```bash
git diff
```

### 5. Değişikliklerinizi Commit Edin

Değişiklikleri Git'e ekleyin:

```bash
git add .
```

Ardından açıklayıcı bir commit oluşturun:

```bash
git commit -m "Add new feature"
```

Örneğin:

```bash
git commit -m "Improve endpoint mapper"
```

### 6. Branch'inizi Fork'unuza Gönderin

Branch'inizi GitHub'daki fork'unuza gönderin:

```bash
git push origin feature/new-feature
```

Örneğin:

```bash
git push origin fix/login-analyzer
```

### 7. Pull Request Oluşturun

Branch'inizi gönderdikten sonra GitHub fork repository'nize gidin.

GitHub genellikle yeni branch'iniz için **Compare & pull request** veya **Open pull request** seçeneğini gösterecektir.

Bu seçeneğe tıklayın.

Pull Request oluştururken:

* Yaptığınız değişiklikleri açıklayın.
* Hangi problemi çözdüğünüzü belirtin.
* Yeni bir özellik eklediyseniz nasıl çalıştığını açıklayın.
* Mümkünse yaptığınız testleri belirtin.

Pull Request'in hedef repository'sinin:

```text
betulakmercann/Injecasst
```

ve hedef branch'in:

```text
main
```

olduğundan emin olun.

Daha sonra **Create pull request** butonuna tıklayın.

### 8. Pull Request İncelemesi

Pull Request oluşturulduktan sonra değişiklikler InjecAsst'in maintainer'ı tarafından incelenir.

Değişiklikler uygun bulunursa Pull Request `main` branch'ine merge edilebilir.

Değişikliklerle ilgili düzenleme istenirse aynı branch üzerinde yeni commit'ler gönderebilirsiniz:

```bash
git add .
git commit -m "Address review feedback"
git push origin feature/new-feature
```

Yeni commit'ler otomatik olarak mevcut Pull Request'e eklenir.

### Katkı Süreci

Genel olarak süreç şu şekildedir:

```text
InjecAsst Official Repository
          │
          │ Fork
          ▼
     Your GitHub Fork
          │
          │ git clone
          ▼
    Local Repository
          │
          │ create branch
          ▼
    Your Feature Branch
          │
          │ changes + commit
          ▼
     Push to Your Fork
          │
          │ Pull Request
          ▼
InjecAsst Official Repository
          │
          │ Review
          ▼
        Merge
```

### Katkı Kuralları

Katkı gönderirken:

* Değişikliklerin güvenlik testi ve araştırması amacıyla uyumlu olması,
* Mevcut özelliklerin gereksiz şekilde bozulmaması,
* Yeni özelliklerin mümkün olduğunca test edilmesi,
* Açıklayıcı commit mesajları kullanılması,
* Pull Request açıklamasının yapılan değişikliği açıkça anlatması,
* Projenin lisans ve marka koşullarına uyulması

beklenmektedir.

Her Pull Request'in kabul edileceği garanti edilmez. Katkıların incelenmesi ve kabul edilmesi InjecAsst projesinin maintainer'ının değerlendirmesine bağlıdır.


## Güvenlik ve Yasal Uyarı

InjecAsst bir güvenlik araştırması ve yetkili test aracıdır.

Aracı yalnızca:

* Sahip olduğunuz sistemlerde,
* Test etmek için açıkça izin aldığınız sistemlerde,
* Kontrollü laboratuvar ortamlarında,
* Eğitim ve güvenlik araştırması amacıyla

kullanın.

Bir sistem üzerinde güvenlik testi gerçekleştirmeden önce gerekli yetkiye sahip olduğunuzdan emin olmak tamamen kullanıcının sorumluluğundadır.

InjecAsst geliştiricileri; yetkisiz erişim, veri ihlali, hizmet kesintisi, veri kaybı, sistem hasarı veya başka herhangi bir hukuka aykırı kullanım sonucunda oluşabilecek doğrudan veya dolaylı zararlardan sorumlu değildir.

Aracın herhangi bir özelliğinin bulunması, kullanıcıya herhangi bir sisteme yetkisiz erişim veya saldırı gerçekleştirme hakkı vermez.

**Yetkiniz olmayan sistemlerde kullanmayın.**

## Lisans ve Marka

InjecAsst kaynak kodu, repository içerisinde bulunan `LICENSE` dosyasında belirtilen lisans koşullarına tabidir.
Kaynak kodunun açık kaynak olarak sunulması, **InjecAsst** 'in  kullanımına otomatik olarak izin verildiği anlamına gelmez.
Projeyi lisans koşullarına uygun şekilde fork edebilir, inceleyebilir veya değiştirebilirsiniz. Ancak değiştirilmiş, fork'lanmış veya türetilmiş bir sürüm:

* Resmi InjecAsst sürümü gibi sunulamaz.
* Resmi InjecAsst repository'si ile karıştırılabilecek şekilde dağıtılamaz.

Değiştirilmiş veya türetilmiş projelerin resmi InjecAsst olmadığı açıkça belirtilmelidir.

InjecAsst'in resmi sürümü ve resmi geliştirmeleri yalnızca aşağıdaki repository üzerinden takip edilmelidir:

```text
https://github.com/betulakmercann/Injecasst
```

## Disclaimer

InjecAsst yalnızca yetkili güvenlik testleri, eğitim, güvenlik araştırmaları ve kontrollü laboratuvar ortamlarında kullanılmalıdır.

Bu yazılımı kullanarak gerçekleştirdiğiniz tüm işlemlerden ve bu işlemlerin hukuki sonuçlarından yalnızca kullanıcı sorumludur.

Geliştiriciler, yazılımın yanlış, yetkisiz veya hukuka aykırı kullanımından doğabilecek sonuçlardan sorumlu değildir.

**Use responsibly. Test only systems you are authorized to test.**
