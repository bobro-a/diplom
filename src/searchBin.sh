#!/usr/bin/env bash
set -euo pipefail

# Имена бинарников, которые нас интересуют
CANDIDATES=(
  connmand      # демон ConnMan
  connmanctl    # CLI-клиент
  *dhcp*
#  *connman*
   *dh*
)

# Стандартные директории с бинарниками
SEARCH_DIRS=(
  /sbin
  /bin
)

found_any=0

echo "=== Поиск бинарников ConnMan ==="

for name in "${CANDIDATES[@]}"; do
  echo
  echo "Ищу бинарник: $name"

  # 1) Попробовать через PATH (вдруг уже в PATH)
  if command -v "$name" >/dev/null 2>&1; then
    path="$(command -v "$name")"
    echo "Найден в PATH: $path"
    found_any=1
    continue
  fi

  # 2) Поиск в стандартных каталогах
  local_found=0
  for dir in "${SEARCH_DIRS[@]}"; do
    if [ -x "${dir}/${name}" ]; then
      echo "Найден в ${dir}: ${dir}/${name}"
      local_found=1
      found_any=1
    fi
  done

  # 3) Если нигде не нашли — использовать find по всей системе (можно ограничить /usr)
  if [ "$local_found" -eq 0 ]; then
    echo "В стандартных путях не найден, запускаю find (может занять время)..."
    find_results=$(find / -type f -name "$name" -perm -111 2>/dev/null || true)
    if [ -n "$find_results" ]; then
      echo "$find_results"
      found_any=1
    else
      echo "Бинарник $name не найден."
    fi
  fi
done

if [ "$found_any" -eq 0 ]; then
  echo
  echo "Никаких бинарников ConnMan не найдено. Возможно, пакет не установлен или собран без установки."
fi