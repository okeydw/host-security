# Host Security 
###### (для казуалов)

- Просмотр логов ssh удачных/неудачных входов + удобный пробан
- Взаимодействие с iptables/ufw/jail2ban. Просмотр правил и логов.
- Проверка на руткиты (rkhunter)
- Анализ `/etc/ssh/sshd_config` и базовые рекомендации
- Логи пользователей/групп и их сессий через `bash_history` и `journalctl`
- Экспорт в txt
---
## Зависимости

`journal`/`ssh`/`ss` - Обязательный

`whois`/`rkhunter` - Опциональный

`fail2ban`/`ufw`/`iptables` - Фаервол

---
## Быстрый старт
```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/okeydw/host-security/main/host-security.py)
```
