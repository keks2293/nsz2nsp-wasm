#!/bin/bash

SOURCE="nsz2nsp.cpp"
OUT_JS="nsz2nsp.js"
ZSTD_DIR="./zstd"
ZSTD_VERSION="1.5.6"

# Проверяем, есть ли уже Zstd
if [ ! -d "$ZSTD_DIR" ] || [ -z "$(ls -A "$ZSTD_DIR")" ]; then
    echo "Zstd not found, downloading v$ZSTD_VERSION..."
    curl -LO "https://github.com/facebook/zstd/releases/download/v$ZSTD_VERSION/zstd-$ZSTD_VERSION.tar.gz"
    tar -xzf "zstd-$ZSTD_VERSION.tar.gz"
    mv "zstd-$ZSTD_VERSION" "$ZSTD_DIR"
    rm "zstd-$ZSTD_VERSION.tar.gz"
else
    echo "Zstd already present in $ZSTD_DIR"
fi

# Находим все .c файлы в lib (исключая папки examples и tests)
ZSTD_SOURCES=$(find "$ZSTD_DIR/lib" -name "*.c" \
    -not -path "*/examples/*" \
    -not -path "*/tests/*" 2>/dev/null)

if [ -z "$ZSTD_SOURCES" ]; then
    echo "Error: No Zstd source files found in $ZSTD_DIR/lib"
    exit 1
fi

echo "Компиляция $SOURCE с локальным Zstd ..."

emcc $SOURCE $ZSTD_SOURCES -o $OUT_JS \
    -I"$ZSTD_DIR/lib" -I"$ZSTD_DIR/lib/common" \
    -s EXPORTED_FUNCTIONS='["_malloc","_free","_nsz_get_output_size","_nsz_convert"]' \
    -s EXPORTED_RUNTIME_METHODS='["HEAPU8","HEAP8","wasmMemory"]' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FILESYSTEM=0 \
    -O3 \
    -flto \
    --no-entry

if [ $? -eq 0 ]; then
    echo "Готово: $OUT_JS и ${OUT_JS/.js/.wasm} созданы."
else
    echo "Ошибка компиляции!"
    exit 1
fi