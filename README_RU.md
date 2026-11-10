<div align="center">

# ◈ SPECTRA
### Аудит безопасности на основе Nmap

**Обнаружение сервисов · Поиск CVE · Приоритизация исправлений**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/Powered%20by-Nmap-4A90E2)
![License](https://img.shields.io/badge/License-MIT-purple)
![Security](https://img.shields.io/badge/Только-с%20разрешения-2ea44f)

**[English](README.md) · Русский**

**Автор: [@zexokkydev](https://t.me/zexokkydev)**

</div>

---

## О проекте

**SPECTRA** — консольная программа на Python для предварительного аудита безопасности. Она запускает ограниченное по интенсивности сканирование Nmap на **разрешённом хосте**, извлекает сведения о сервисах и CPE, сопоставляет их с записями CVE из базы NVD и формирует HTML- и JSON-отчёты.

### Возможности

- **Обнаружение сервисов:** открытые TCP-порты, названия служб, версии продуктов, CPE.
- **Поиск CVE:** запросы к NVD API 2.0, описания, оценки CVSS и уровни критичности.
- **Отчёты:** адаптивный HTML в тёмной теме и машиночитаемый JSON.
- **Безопасные настройки:** без запуска эксплойтов, перебора паролей и агрессивных NSE-скриптов.
- **Анализ XML:** работа с ранее сохранёнными результатами Nmap.

## Установка

Понадобятся Python 3.10+ и [Nmap](https://nmap.org/download.html), доступный через PATH.

```bash
git clone https://github.com/hexokryn/spectra-nmap-auditor.git
cd spectra-nmap-auditor
python -m pip install -r requirements.txt
```

Сторонние библиотеки Python не требуются.

## Использование

Сканирование собственного хоста или хоста, на проверку которого есть явное разрешение:

```bash
python spectra.py example.org --authorized --output reports
```

Анализ готового XML-файла Nmap без нового сканирования:

```bash
python spectra.py --xml scan.xml --output reports
```

Необязательный API-ключ NVD для повышения лимитов запросов:

```bash
export NVD_API_KEY="your_api_key"
```

В Windows PowerShell: `$env:NVD_API_KEY="your_api_key"`.

### Результаты

```text
reports/
├── report.html     # отчёт для браузера
└── report.json     # структурированные данные
```

### Принцип работы

```text
Разрешённый хост / XML Nmap
             │
             ▼
      Поиск сервисов
             │
             ▼
       Извлечение CPE
             │
             ▼
      Поиск CVE в NVD
             │
             ▼
      HTML + JSON отчёты
```

## Точность и ограничения

**Совпадение CPE с CVE не означает подтверждённую уязвимость.** Версии могут определяться неточно, данные CPE бывают неполными, а некоторые CVE неприменимы к конкретной конфигурации. Перед выводами нужно самостоятельно проверить версию и условия уязвимости. Доступность и ограничения API NVD могут влиять на результаты.

Сканируйте только системы, принадлежащие вам или проверяемые с разрешения владельца. Программа не эксплуатирует уязвимости.

## Структура проекта

```text
spectra.py           CLI, Nmap, NVD, генерация отчётов
requirements.txt     Информация о зависимостях
README.md            Документация на английском
README_RU.md         Документация на русском
LICENSE              Лицензия MIT
.gitignore           Исключения для Git
```

## Контакты

Telegram-канал разработчика: **[t.me/zexokkydev](https://t.me/zexokkydev)**

## Лицензия

MIT. Подробности в [LICENSE](LICENSE).
