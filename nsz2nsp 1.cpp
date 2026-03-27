#include <cstdint>
#include <cstring>
#include <vector>
#include <zstd.h>
#include <emscripten.h>

#pragma pack(push, 1)
struct PFS0Header {
    char magic[4];
    uint32_t version;
    uint32_t file_count;
    uint32_t string_table_size;
};

struct NSPFileEntry {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t flags;
    uint32_t name_offset;
};

struct NSZFileEntry {
    uint64_t data_offset;
    uint64_t compressed_size;
    uint64_t original_size;
    uint32_t flags;      // bit 0: 1 = Zstd compressed
    uint32_t name_offset;
};
#pragma pack(pop)

// Вспомогательная функция для записи в буфер
template<typename T>
void write_to_buffer(uint8_t* buffer, size_t& offset, const T& value) {
    std::memcpy(buffer + offset, &value, sizeof(T));
    offset += sizeof(T);
}

extern "C" {

// Функция для вычисления размера выходных данных (с учётом паддинга)
size_t EMSCRIPTEN_KEEPALIVE nsz_get_output_size(const uint8_t* input, size_t input_size) {
    if (input_size < sizeof(PFS0Header)) return 0;

    PFS0Header header;
    std::memcpy(&header, input, sizeof(header));

    // Если уже NSP (PFS0), просто копируем
    if (std::memcmp(header.magic, "PFS0", 4) == 0) {
        return input_size;
    }

    if (std::memcmp(header.magic, "NSZ0", 4) != 0) return 0;

    uint32_t file_count = header.file_count;
    uint32_t string_table_size = header.string_table_size;

    size_t entries_size = file_count * sizeof(NSZFileEntry);
    if (input_size < sizeof(PFS0Header) + entries_size + string_table_size) return 0;

    // Базовый размер = заголовок + записи + строки
    uint64_t total_size = sizeof(PFS0Header) + file_count * sizeof(NSPFileEntry) + string_table_size;

    // Выравнивание начала первого файла до 0x200
    uint64_t first_file_padding = (0x200 - (total_size % 0x200)) % 0x200;
    total_size += first_file_padding;

    // Обрабатываем записи, чтобы узнать размеры данных и добавить паддинг после каждого файла
    size_t offset = sizeof(PFS0Header);
    for (uint32_t i = 0; i < file_count; ++i) {
        NSZFileEntry entry;
        std::memcpy(&entry, input + offset, sizeof(entry));
        offset += sizeof(entry);

        bool compressed = (entry.flags & 1) != 0;
        uint64_t data_size = compressed ? entry.original_size : entry.compressed_size;
        total_size += data_size;
        // Паддинг после данных до следующей границы 0x200
        uint64_t padding = (0x200 - (total_size % 0x200)) % 0x200;
        total_size += padding;
    }

    return total_size;
}

// Основная функция конвертации
size_t EMSCRIPTEN_KEEPALIVE nsz_convert(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) {
    if (!input || !output) return 0;
    if (input_size < sizeof(PFS0Header)) return 0;

    PFS0Header header;
    std::memcpy(&header, input, sizeof(header));

    // Если уже NSP, просто копируем
    if (std::memcmp(header.magic, "PFS0", 4) == 0) {
        if (output_size < input_size) return 0;
        std::memcpy(output, input, input_size);
        return input_size;
    }

    if (std::memcmp(header.magic, "NSZ0", 4) != 0) return 0;

    uint32_t file_count = header.file_count;
    uint32_t string_table_size = header.string_table_size;

    size_t entries_size = file_count * sizeof(NSZFileEntry);
    if (input_size < sizeof(PFS0Header) + entries_size + string_table_size) return 0;

    // Проверяем, что размер выходного буфера совпадает с вычисленным
    size_t expected_output_size = nsz_get_output_size(input, input_size);
    if (expected_output_size == 0 || expected_output_size > output_size) return 0;

    // --- Подготовка к вычислению смещений с учётом паддинга ---
    std::vector<NSPFileEntry> new_entries(file_count);
    std::vector<uint64_t> file_paddings(file_count, 0); // паддинг после каждого файла

    // Начальное смещение после заголовка, записей и строк
    uint64_t current_offset = sizeof(PFS0Header) + file_count * sizeof(NSPFileEntry) + string_table_size;

    // Паддинг перед первым файлом
    uint64_t first_file_padding = (0x200 - (current_offset % 0x200)) % 0x200;
    current_offset += first_file_padding;

    // Читаем NSZ-записи и вычисляем смещения
    size_t in_offset = sizeof(PFS0Header);
    for (uint32_t i = 0; i < file_count; ++i) {
        NSZFileEntry entry;
        std::memcpy(&entry, input + in_offset, sizeof(entry));
        in_offset += sizeof(entry);

        bool compressed = (entry.flags & 1) != 0;
        uint64_t data_size = compressed ? entry.original_size : entry.compressed_size;

        new_entries[i].data_offset = current_offset;
        new_entries[i].data_size = data_size;
        new_entries[i].flags = 0;
        new_entries[i].name_offset = entry.name_offset;

        current_offset += data_size;
        uint64_t padding = (0x200 - (current_offset % 0x200)) % 0x200;
        file_paddings[i] = padding;
        current_offset += padding;
    }

    // --- Запись выходного файла ---
    size_t out_pos = 0;

    // Заголовок
    PFS0Header new_header;
    std::memcpy(new_header.magic, "PFS0", 4);
    new_header.version = 0;
    new_header.file_count = file_count;
    new_header.string_table_size = string_table_size;
    write_to_buffer(output, out_pos, new_header);

    // Записи файлов (пока с вычисленными смещениями)
    for (const auto& entry : new_entries) {
        write_to_buffer(output, out_pos, entry);
    }

    // Строковая таблица
    std::memcpy(output + out_pos, input + sizeof(PFS0Header) + entries_size, string_table_size);
    out_pos += string_table_size;

    // Паддинг перед первым файлом
    if (first_file_padding > 0) {
        std::memset(output + out_pos, 0, first_file_padding);
        out_pos += first_file_padding;
    }

    // Инициализация декомпрессора Zstd
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) return 0;

    // Обработка каждого файла
    in_offset = sizeof(PFS0Header);
    for (uint32_t i = 0; i < file_count; ++i) {
        NSZFileEntry entry;
        std::memcpy(&entry, input + in_offset, sizeof(entry));
        in_offset += sizeof(entry);

        bool compressed = (entry.flags & 1) != 0;

        if (compressed) {
            // Распаковка
            size_t result = ZSTD_decompressDCtx(dctx,
                                                 output + out_pos, entry.original_size,
                                                 input + entry.data_offset, entry.compressed_size);
            if (ZSTD_isError(result) || result != entry.original_size) {
                ZSTD_freeDCtx(dctx);
                return 0;
            }
        } else {
            // Копирование
            std::memcpy(output + out_pos, input + entry.data_offset, entry.compressed_size);
        }
        out_pos += compressed ? entry.original_size : entry.compressed_size;

        // Паддинг после файла
        if (file_paddings[i] > 0) {
            std::memset(output + out_pos, 0, file_paddings[i]);
            out_pos += file_paddings[i];
        }
    }

    ZSTD_freeDCtx(dctx);

    // Финальная проверка
    if (out_pos != output_size) return 0;

    return out_pos;
}

} // extern "C"