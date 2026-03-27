#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <zstd.h>
#include <emscripten.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/console.h>
#define DEBUG_LOG(msg) emscripten_console_log(msg)
#define DEBUG_LOG_NUM(n) { char buf[64]; sprintf(buf, "%lld", (long long)n); emscripten_console_log(buf); }
#else
#define DEBUG_LOG(msg)
#define DEBUG_LOG_NUM(n)
#endif

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

// Структуры NCZ (из спецификации nsz)
struct NczSection {
    uint64_t offset;
    uint64_t size;
    uint64_t cryptoType;
    uint64_t padding;
    uint8_t cryptoKey[16];
    uint8_t cryptoCounter[16];
};

struct NczHeader {
    uint64_t magic;            // должно быть 0x4E544345535A434E ("NCZSECTN")
    uint64_t section_count;    // количество секций
};
#pragma pack(pop)

const size_t NCA_HEADER_SIZE = 0x4000;  // первые 0x4000 байт - заголовок NCA
const uint64_t NCZ_MAGIC = 0x4E544345535A434EULL; // "NCZSECTN" в little-endian

// ----------------------------------------------------------------------
// Вспомогательные функции
// ----------------------------------------------------------------------

std::string decode_name(const uint8_t* data, size_t max_len) {
    if (max_len == 0) return "";
    if (max_len >= 2 && data[0] != 0 && data[1] == 0) {
        std::u16string u16;
        for (size_t i = 0; i + 1 < max_len; i += 2) {
            char16_t ch = data[i] | (data[i+1] << 8);
            if (ch == 0) break;
            u16.push_back(ch);
        }
        std::string utf8;
        for (char16_t ch : u16) {
            if (ch < 0x80) utf8.push_back((char)ch);
            else utf8.push_back('?');
        }
        return utf8;
    } else {
        size_t len = strnlen((const char*)data, max_len);
        return std::string((const char*)data, len);
    }
}

// Проверка сигнатуры NCZ (по смещению 0x4000)
bool check_ncz_magic(const uint8_t* data, size_t size) {
    if (size < NCA_HEADER_SIZE + sizeof(uint64_t)) return false;
    uint64_t magic;
    std::memcpy(&magic, data + NCA_HEADER_SIZE, sizeof(magic));
    return magic == NCZ_MAGIC;
}

// Парсинг заголовка NCZ, возвращает decompressed_size через параметр
bool parse_ncz_header(const uint8_t* data, size_t size,
                      std::vector<NczSection>& sections,
                      size_t& compressed_offset,
                      size_t& compressed_size,
                      uint64_t& decompressed_size) {
    if (size < NCA_HEADER_SIZE + sizeof(NczHeader)) {
        DEBUG_LOG("NCZ: file too small for headers");
        return false;
    }
    const uint8_t* ncz_start = data + NCA_HEADER_SIZE;
    NczHeader header;
    std::memcpy(&header, ncz_start, sizeof(header));
    if (header.magic != NCZ_MAGIC) {
        DEBUG_LOG("NCZ: invalid magic");
        return false;
    }
    DEBUG_LOG("NCZ: valid magic found");
    DEBUG_LOG_NUM(header.section_count);
    if (header.section_count > 100) {
        DEBUG_LOG("NCZ: suspiciously many sections");
        return false;
    }
    size_t sections_size = header.section_count * sizeof(NczSection);
    if (size < NCA_HEADER_SIZE + sizeof(NczHeader) + sections_size) {
        DEBUG_LOG("NCZ: too small for all sections");
        return false;
    }
    sections.resize(header.section_count);
    std::memcpy(sections.data(),
                ncz_start + sizeof(NczHeader),
                sections_size);
    compressed_offset = NCA_HEADER_SIZE + sizeof(NczHeader) + sections_size;
    compressed_size = size - compressed_offset;
    DEBUG_LOG("NCZ: compressed data offset: ");
    DEBUG_LOG_NUM(compressed_offset);
    DEBUG_LOG("NCZ: compressed data size: ");
    DEBUG_LOG_NUM(compressed_size);
    // Определяем размер после распаковки (пробная декомпрессия)
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) {
        DEBUG_LOG("NCZ: cannot create ZSTD context");
        return false;
    }
    size_t result = ZSTD_decompressDCtx(dctx, nullptr, 0,
                                         data + compressed_offset,
                                         compressed_size);
    ZSTD_freeDCtx(dctx);
    if (ZSTD_isError(result)) {
        DEBUG_LOG("NCZ: ZSTD_getDecompressedSize failed");
        return false;
    }
    decompressed_size = result;
    DEBUG_LOG("NCZ: decompressed size: ");
    DEBUG_LOG_NUM(decompressed_size);
    return true;
}

template<typename T>
void write_to_buffer(uint8_t* buffer, size_t& offset, const T& value) {
    std::memcpy(buffer + offset, &value, sizeof(T));
    offset += sizeof(T);
}

bool hasNullTerminator(const uint8_t* string_table, uint32_t size) {
    if (size == 0) return false;
    return string_table[size - 1] == 0;
}

uint32_t fixTooShortHeaderSize(uint32_t reported_size, uint32_t min_expected_size) {
    if (reported_size < min_expected_size && reported_size > 0) {
        DEBUG_LOG("Warning: Header size too short. Fixing...");
        return min_expected_size;
    }
    return reported_size;
}

bool checkHeaderOverlap(uint64_t header_end, uint64_t first_file_start) {
    if (first_file_start < header_end) {
        DEBUG_LOG("Warning: PFS0 header overlaps with first file. Adjusting...");
        return true;
    }
    return false;
}

uint64_t calculateProperHeaderPadding(uint64_t current_pos) {
    const uint64_t PFS0_ALIGNMENT = 0x200;
    uint64_t padding = (PFS0_ALIGNMENT - (current_pos % PFS0_ALIGNMENT)) % PFS0_ALIGNMENT;
    if (padding == 0) return 0;
    DEBUG_LOG("Calculating proper PFS0 header padding: ");
    DEBUG_LOG_NUM(padding);
    return padding;
}

// ----------------------------------------------------------------------
// Основные структуры
// ----------------------------------------------------------------------

struct ValidEntry {
    std::string name;
    uint64_t in_offset;
    uint64_t in_size;         // сжатый размер (для NCZ) или обычный
    uint64_t original_size;   // для сжатых файлов (после распаковки)
    bool compressed;          // флаг сжатия (для современного NSZ)
    bool is_ncz;              // является ли NCZ (по имени)
    uint32_t name_offset;     // будет обновлён после создания новой строковой таблицы
    std::vector<NczSection> sections; // секции NCZ (если есть)
    size_t compressed_offset; // смещение сжатых данных внутри NCZ (заполняется при парсинге)
    size_t compressed_size;   // размер сжатых данных
};

// ----------------------------------------------------------------------
// Экспортируемые функции
// ----------------------------------------------------------------------

extern "C" {

size_t EMSCRIPTEN_KEEPALIVE nsz_get_output_size(const uint8_t* input, size_t input_size) {
    DEBUG_LOG("nsz_get_output_size called");
    if (input_size < sizeof(PFS0Header)) {
        DEBUG_LOG("Error: input too small for header");
        return 0;
    }

    PFS0Header header;
    std::memcpy(&header, input, sizeof(header));

    char magic_str[5] = {0};
    std::memcpy(magic_str, header.magic, 4);
    DEBUG_LOG("Magic: ");
    DEBUG_LOG(magic_str);

    bool is_modern_nsz = (std::memcmp(header.magic, "NSZ0", 4) == 0);
    bool is_legacy_nsz_or_nsp = (std::memcmp(header.magic, "PFS0", 4) == 0);

    if (!is_modern_nsz && !is_legacy_nsz_or_nsp) {
        DEBUG_LOG("Unknown magic");
        return 0;
    }

    uint32_t orig_file_count = header.file_count;
    uint32_t string_table_size = header.string_table_size;

    uint32_t min_expected_header = sizeof(PFS0Header);
    string_table_size = fixTooShortHeaderSize(string_table_size, min_expected_header);

    DEBUG_LOG("Original file count: ");
    DEBUG_LOG_NUM(orig_file_count);
    DEBUG_LOG("String table size: ");
    DEBUG_LOG_NUM(string_table_size);

    if (orig_file_count == 0) {
        DEBUG_LOG("Error: file_count is 0");
        return 0;
    }

    size_t entries_size_input;
    if (is_modern_nsz) {
        entries_size_input = orig_file_count * sizeof(NSZFileEntry);
    } else {
        entries_size_input = orig_file_count * sizeof(NSPFileEntry);
    }

    if (input_size < sizeof(PFS0Header) + entries_size_input) {
        DEBUG_LOG("Error: input too small for entries");
        return 0;
    }

    // Определяем реальный размер строковой таблицы
    uint32_t actual_string_table_size = string_table_size;
    const uint8_t* string_table = nullptr;
    const uint8_t* original_entries = input + sizeof(PFS0Header);
    bool needs_null_terminator = false;

    if (string_table_size == 0 && orig_file_count > 0) {
        size_t start_of_string_area = sizeof(PFS0Header) + entries_size_input;
        uint64_t first_file_offset = 0;
        if (is_modern_nsz) {
            NSZFileEntry first_entry;
            std::memcpy(&first_entry, original_entries, sizeof(first_entry));
            first_file_offset = first_entry.data_offset;
        } else {
            NSPFileEntry first_entry;
            std::memcpy(&first_entry, original_entries, sizeof(first_entry));
            first_file_offset = first_entry.data_offset;
        }

        uint64_t header_end = sizeof(PFS0Header) + entries_size_input;
        if (checkHeaderOverlap(header_end, first_file_offset)) {
            first_file_offset = header_end + 0x200;
        }

        if (first_file_offset > start_of_string_area && first_file_offset <= input_size) {
            actual_string_table_size = first_file_offset - start_of_string_area;
            DEBUG_LOG("Determined string_table_size: ");
            DEBUG_LOG_NUM(actual_string_table_size);
        } else {
            DEBUG_LOG("Warning: Could not determine string table. Using minimal size.");
            actual_string_table_size = 1;
        }
    }

    if (input_size < sizeof(PFS0Header) + entries_size_input + actual_string_table_size) {
        DEBUG_LOG("Error: input too small for entries + string table");
        return 0;
    }

    string_table = input + sizeof(PFS0Header) + entries_size_input;

    if (actual_string_table_size > 0 && !hasNullTerminator(string_table, actual_string_table_size)) {
        DEBUG_LOG("Warning: String table missing null terminator. Will add during conversion.");
        needs_null_terminator = true;
    }

    // Фильтруем валидные записи
    std::vector<ValidEntry> valid_entries;

    for (uint32_t i = 0; i < orig_file_count; ++i) {
        uint64_t off, sz, orig_sz = 0;
        bool comp = false;
        uint32_t name_off = 0;

        if (is_modern_nsz) {
            NSZFileEntry entry;
            std::memcpy(&entry, original_entries + i * sizeof(NSZFileEntry), sizeof(entry));
            off = entry.data_offset;
            sz = entry.compressed_size;
            orig_sz = entry.original_size;
            comp = (entry.flags & 1) != 0;
            name_off = entry.name_offset;
        } else {
            NSPFileEntry entry;
            std::memcpy(&entry, original_entries + i * sizeof(NSPFileEntry), sizeof(entry));
            off = entry.data_offset;
            sz = entry.data_size;
            name_off = entry.name_offset;
        }

        std::string name;
        if (actual_string_table_size > 0 && name_off < actual_string_table_size) {
            name = decode_name(string_table + name_off, actual_string_table_size - name_off);
        } else {
            name = "unknown_" + std::to_string(i);
        }

        bool valid = true;

        if (off + sz > input_size) {
            DEBUG_LOG("Entry ");
            DEBUG_LOG_NUM(i);
            DEBUG_LOG(" invalid: offset+size out of bounds");
            valid = false;
        }
        if (sz == 0) {
            DEBUG_LOG("Entry ");
            DEBUG_LOG_NUM(i);
            DEBUG_LOG(" invalid: zero size");
            valid = false;
        }

        bool is_ncz = (name.size() > 4 && name.substr(name.size() - 4) == ".ncz");

        if (valid) {
            ValidEntry ve;
            ve.name = name;
            ve.in_offset = off;
            ve.in_size = sz;
            ve.original_size = orig_sz;
            ve.compressed = comp;
            ve.is_ncz = is_ncz;
            ve.name_offset = name_off;
            ve.compressed_offset = 0;
            ve.compressed_size = 0;

            // Если это NCZ, пробуем распарсить заголовок
            if (is_ncz && off + sz <= input_size) {
                size_t comp_off, comp_sz;
                uint64_t decomp_sz;
                if (parse_ncz_header(input + off, sz, ve.sections, comp_off, comp_sz, decomp_sz)) {
                    ve.compressed_offset = comp_off;
                    ve.compressed_size = comp_sz;
                    ve.original_size = NCA_HEADER_SIZE + decomp_sz; // заголовок NCA + распакованные данные
                }
            }

            valid_entries.push_back(ve);
        }
    }

    uint32_t file_count = valid_entries.size();
    DEBUG_LOG("Valid file count after filtering: ");
    DEBUG_LOG_NUM(file_count);

    if (file_count == 0) {
        DEBUG_LOG("Error: no valid files found");
        return 0;
    }

    // Отладочный вывод
    DEBUG_LOG("--- Valid entries details ---");
    for (uint32_t i = 0; i < file_count; ++i) {
        const auto& ve = valid_entries[i];
        DEBUG_LOG("Entry ");
        DEBUG_LOG_NUM(i);
        DEBUG_LOG(" name: ");
        DEBUG_LOG(ve.name.c_str());
        DEBUG_LOG(" in_offset: ");
        DEBUG_LOG_NUM(ve.in_offset);
        DEBUG_LOG(" in_size: ");
        DEBUG_LOG_NUM(ve.in_size);
        if (ve.is_ncz) {
            DEBUG_LOG(" is NCZ, sections: ");
            DEBUG_LOG_NUM(ve.sections.size());
            DEBUG_LOG(" original_size: ");
            DEBUG_LOG_NUM(ve.original_size);
        } else if (ve.compressed) {
            DEBUG_LOG(" compressed original_size: ");
            DEBUG_LOG_NUM(ve.original_size);
        }
    }

    // Создаём новую строковую таблицу с заменой .ncz на .nca
    std::vector<uint8_t> new_string_table;
    std::vector<uint32_t> new_name_offsets(file_count);

    for (uint32_t i = 0; i < file_count; ++i) {
        std::string name = valid_entries[i].name;
        if (valid_entries[i].is_ncz) {
            size_t pos = name.rfind(".ncz");
            if (pos != std::string::npos) {
                name.replace(pos, 4, ".nca");
            }
        }
        new_name_offsets[i] = new_string_table.size();
        new_string_table.insert(new_string_table.end(), name.begin(), name.end());
        new_string_table.push_back(0);
    }

    if (needs_null_terminator && (new_string_table.empty() || new_string_table.back() != 0)) {
        new_string_table.push_back(0);
    }

    uint32_t new_string_table_size = new_string_table.size();

    // Обновляем name_offset
    for (uint32_t i = 0; i < file_count; ++i) {
        valid_entries[i].name_offset = new_name_offsets[i];
    }

    // Размер таблицы записей выходного файла
    uint64_t file_entry_table_size = file_count * sizeof(NSPFileEntry);

    // Вычисляем базовый размер заголовка
    uint64_t header_base = sizeof(PFS0Header) + file_entry_table_size + new_string_table_size;
    uint64_t header_padding = calculateProperHeaderPadding(header_base);
    uint64_t total_size = header_base + header_padding;

    // Добавляем размеры данных
    for (uint32_t i = 0; i < file_count; ++i) {
        const auto& ve = valid_entries[i];
        uint64_t out_size = ve.is_ncz ? ve.original_size : ve.in_size;
        if (!ve.is_ncz && ve.compressed) {
            out_size = ve.original_size;
        }

        total_size += out_size;
        uint64_t padding = (0x200 - (total_size % 0x200)) % 0x200;
        total_size += padding;
    }

    DEBUG_LOG("Total output size: ");
    DEBUG_LOG_NUM(total_size);
    return total_size;
}

size_t EMSCRIPTEN_KEEPALIVE nsz_convert(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) {
    DEBUG_LOG("nsz_convert called");
    if (!input || !output) {
        DEBUG_LOG("Error: null input/output");
        return 0;
    }
    if (input_size < sizeof(PFS0Header)) {
        DEBUG_LOG("Error: input too small");
        return 0;
    }

    PFS0Header header;
    std::memcpy(&header, input, sizeof(header));

    bool is_modern_nsz = (std::memcmp(header.magic, "NSZ0", 4) == 0);
    bool is_legacy_nsz_or_nsp = (std::memcmp(header.magic, "PFS0", 4) == 0);

    if (!is_modern_nsz && !is_legacy_nsz_or_nsp) {
        DEBUG_LOG("Error: unknown magic");
        return 0;
    }

    uint32_t orig_file_count = header.file_count;
    uint32_t string_table_size = header.string_table_size;

    uint32_t min_expected_header = sizeof(PFS0Header);
    string_table_size = fixTooShortHeaderSize(string_table_size, min_expected_header);

    size_t entries_size_input;
    if (is_modern_nsz) {
        entries_size_input = orig_file_count * sizeof(NSZFileEntry);
    } else {
        entries_size_input = orig_file_count * sizeof(NSPFileEntry);
    }

    if (input_size < sizeof(PFS0Header) + entries_size_input) {
        DEBUG_LOG("Error: input too small for entries");
        return 0;
    }

    // Определяем реальный размер строковой таблицы
    uint32_t actual_string_table_size = string_table_size;
    const uint8_t* string_table = nullptr;
    const uint8_t* original_entries = input + sizeof(PFS0Header);
    bool needs_null_terminator = false;

    if (string_table_size == 0 && orig_file_count > 0) {
        size_t start_of_string_area = sizeof(PFS0Header) + entries_size_input;
        uint64_t first_file_offset = 0;
        if (is_modern_nsz) {
            NSZFileEntry first_entry;
            std::memcpy(&first_entry, original_entries, sizeof(first_entry));
            first_file_offset = first_entry.data_offset;
        } else {
            NSPFileEntry first_entry;
            std::memcpy(&first_entry, original_entries, sizeof(first_entry));
            first_file_offset = first_entry.data_offset;
        }

        uint64_t header_end = sizeof(PFS0Header) + entries_size_input;
        if (checkHeaderOverlap(header_end, first_file_offset)) {
            first_file_offset = header_end + 0x200;
        }

        if (first_file_offset > start_of_string_area && first_file_offset <= input_size) {
            actual_string_table_size = first_file_offset - start_of_string_area;
            DEBUG_LOG("Determined string_table_size (convert): ");
            DEBUG_LOG_NUM(actual_string_table_size);
        } else {
            DEBUG_LOG("Warning (convert): Could not determine string table. Using minimal size.");
            actual_string_table_size = 1;
        }
    }

    if (input_size < sizeof(PFS0Header) + entries_size_input + actual_string_table_size) {
        DEBUG_LOG("Error: input too small for entries + string table (convert)");
        return 0;
    }

    string_table = input + sizeof(PFS0Header) + entries_size_input;

    if (actual_string_table_size > 0 && !hasNullTerminator(string_table, actual_string_table_size)) {
        DEBUG_LOG("Warning: String table missing null terminator. Will add during conversion.");
        needs_null_terminator = true;
    }

    // Фильтруем валидные записи
    std::vector<ValidEntry> valid_entries;

    for (uint32_t i = 0; i < orig_file_count; ++i) {
        uint64_t off, sz, orig_sz = 0;
        bool comp = false;
        uint32_t name_off = 0;

        if (is_modern_nsz) {
            NSZFileEntry entry;
            std::memcpy(&entry, original_entries + i * sizeof(NSZFileEntry), sizeof(entry));
            off = entry.data_offset;
            sz = entry.compressed_size;
            orig_sz = entry.original_size;
            comp = (entry.flags & 1) != 0;
            name_off = entry.name_offset;
        } else {
            NSPFileEntry entry;
            std::memcpy(&entry, original_entries + i * sizeof(NSPFileEntry), sizeof(entry));
            off = entry.data_offset;
            sz = entry.data_size;
            name_off = entry.name_offset;
        }

        std::string name;
        if (actual_string_table_size > 0 && name_off < actual_string_table_size) {
            name = decode_name(string_table + name_off, actual_string_table_size - name_off);
        } else {
            name = "unknown_" + std::to_string(i);
        }

        bool valid = true;

        if (off + sz > input_size) {
            DEBUG_LOG("Entry ");
            DEBUG_LOG_NUM(i);
            DEBUG_LOG(" invalid: offset+size out of bounds");
            valid = false;
        }
        if (sz == 0) {
            DEBUG_LOG("Entry ");
            DEBUG_LOG_NUM(i);
            DEBUG_LOG(" invalid: zero size");
            valid = false;
        }

        bool is_ncz = (name.size() > 4 && name.substr(name.size() - 4) == ".ncz");

        if (valid) {
            ValidEntry ve;
            ve.name = name;
            ve.in_offset = off;
            ve.in_size = sz;
            ve.original_size = orig_sz;
            ve.compressed = comp;
            ve.is_ncz = is_ncz;
            ve.name_offset = name_off;
            ve.compressed_offset = 0;
            ve.compressed_size = 0;

            if (is_ncz && off + sz <= input_size) {
                size_t comp_off, comp_sz;
                uint64_t decomp_sz;
                if (parse_ncz_header(input + off, sz, ve.sections, comp_off, comp_sz, decomp_sz)) {
                    ve.compressed_offset = comp_off;
                    ve.compressed_size = comp_sz;
                    ve.original_size = NCA_HEADER_SIZE + decomp_sz;
                }
            }

            valid_entries.push_back(ve);
        }
    }

    uint32_t file_count = valid_entries.size();
    DEBUG_LOG("Valid file count after filtering: ");
    DEBUG_LOG_NUM(file_count);

    if (file_count == 0) {
        DEBUG_LOG("Error: no valid files found");
        return 0;
    }

    DEBUG_LOG("--- Valid entries details (convert) ---");
    for (uint32_t i = 0; i < file_count; ++i) {
        const auto& ve = valid_entries[i];
        DEBUG_LOG("Entry ");
        DEBUG_LOG_NUM(i);
        DEBUG_LOG(" name: ");
        DEBUG_LOG(ve.name.c_str());
        DEBUG_LOG(" in_offset: ");
        DEBUG_LOG_NUM(ve.in_offset);
        DEBUG_LOG(" in_size: ");
        DEBUG_LOG_NUM(ve.in_size);
        if (ve.is_ncz) {
            DEBUG_LOG(" is NCZ, sections: ");
            DEBUG_LOG_NUM(ve.sections.size());
        }
    }

    // Создаём новую строковую таблицу
    std::vector<uint8_t> new_string_table;
    std::vector<uint32_t> new_name_offsets(file_count);

    for (uint32_t i = 0; i < file_count; ++i) {
        std::string name = valid_entries[i].name;
        if (valid_entries[i].is_ncz) {
            size_t pos = name.rfind(".ncz");
            if (pos != std::string::npos) {
                name.replace(pos, 4, ".nca");
            }
        }
        new_name_offsets[i] = new_string_table.size();
        new_string_table.insert(new_string_table.end(), name.begin(), name.end());
        new_string_table.push_back(0);
    }

    if (needs_null_terminator && (new_string_table.empty() || new_string_table.back() != 0)) {
        new_string_table.push_back(0);
    }

    uint32_t new_string_table_size = new_string_table.size();

    for (uint32_t i = 0; i < file_count; ++i) {
        valid_entries[i].name_offset = new_name_offsets[i];
    }

    // Проверяем ожидаемый выходной размер
    size_t expected_output_size = nsz_get_output_size(input, input_size);
    if (expected_output_size == 0 || expected_output_size != output_size) {
        DEBUG_LOG("Error: output size mismatch");
        return 0;
    }

    uint64_t file_entry_table_size = file_count * sizeof(NSPFileEntry);
    uint64_t header_base = sizeof(PFS0Header) + file_entry_table_size + new_string_table_size;
    uint64_t header_padding = calculateProperHeaderPadding(header_base);
    uint64_t data_start = header_base + header_padding;

    // Вычисляем точные выходные размеры
    std::vector<uint64_t> exact_sizes(file_count);
    for (uint32_t i = 0; i < file_count; ++i) {
        const auto& ve = valid_entries[i];
        if (ve.is_ncz) {
            exact_sizes[i] = ve.original_size; // уже вычислено при парсинге
        } else if (ve.compressed) {
            exact_sizes[i] = ve.original_size;
        } else {
            exact_sizes[i] = ve.in_size;
        }
    }

    // Вычисляем новые смещения и паддинги
    std::vector<NSPFileEntry> new_entries(file_count);
    std::vector<uint64_t> file_paddings(file_count, 0);

    uint64_t out_data_offset = data_start;
    for (uint32_t i = 0; i < file_count; ++i) {
        new_entries[i].data_offset = out_data_offset;
        new_entries[i].data_size = exact_sizes[i];
        new_entries[i].flags = 0;
        new_entries[i].name_offset = valid_entries[i].name_offset;

        out_data_offset += exact_sizes[i];
        uint64_t padding = (0x200 - (out_data_offset % 0x200)) % 0x200;
        file_paddings[i] = padding;
        out_data_offset += padding;
    }

    // Запись выходного буфера
    size_t out_pos = 0;

    PFS0Header new_header;
    std::memcpy(new_header.magic, "PFS0", 4);
    new_header.version = 0;
    new_header.file_count = file_count;
    new_header.string_table_size = new_string_table_size;
    write_to_buffer(output, out_pos, new_header);

    for (const auto& entry : new_entries) {
        write_to_buffer(output, out_pos, entry);
    }

    std::memcpy(output + out_pos, new_string_table.data(), new_string_table_size);
    out_pos += new_string_table_size;

    if (header_padding > 0) {
        std::memset(output + out_pos, 0, header_padding);
        out_pos += header_padding;
    }

    // Декомпрессия и копирование данных
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    if (!dctx) {
        DEBUG_LOG("Error: cannot create ZSTD context");
        return 0;
    }

    for (uint32_t i = 0; i < file_count; ++i) {
        const auto& ve = valid_entries[i];

        DEBUG_LOG("Processing file ");
        DEBUG_LOG_NUM(i);
        DEBUG_LOG(" name: ");
        DEBUG_LOG(ve.name.c_str());
        DEBUG_LOG(" expected size: ");
        DEBUG_LOG_NUM(exact_sizes[i]);

        if (ve.is_ncz) {
            // Используем сохранённые ve.compressed_offset и ve.original_size
            const uint8_t* data = input + ve.in_offset;
            // Копируем заголовок NCA (первые 0x4000 байт)
            if (ve.in_size < NCA_HEADER_SIZE) {
                DEBUG_LOG("Error: NCZ too small for NCA header");
                ZSTD_freeDCtx(dctx);
                return 0;
            }
            std::memcpy(output + out_pos, data, NCA_HEADER_SIZE);
            out_pos += NCA_HEADER_SIZE;

            // Пропускаем заголовок NCZ и секции, переходим к сжатым данным
            const uint8_t* compressed_data = data + ve.compressed_offset;
            size_t compressed_size = ve.compressed_size;

            // Распаковываем
            size_t decompressed_size = ZSTD_decompressDCtx(dctx,
                                                            output + out_pos,
                                                            exact_sizes[i] - NCA_HEADER_SIZE,
                                                            compressed_data,
                                                            compressed_size);
            if (ZSTD_isError(decompressed_size)) {
                DEBUG_LOG("Error: NCZ decompression failed");
                DEBUG_LOG(ZSTD_getErrorName(decompressed_size));
                ZSTD_freeDCtx(dctx);
                return 0;
            }
            out_pos += decompressed_size;
        } else if (ve.compressed) {
            size_t decompressed_size = ZSTD_decompressDCtx(dctx,
                                                            output + out_pos,
                                                            ve.original_size,
                                                            input + ve.in_offset,
                                                            ve.in_size);
            if (ZSTD_isError(decompressed_size) || decompressed_size != ve.original_size) {
                DEBUG_LOG("Error: Zstd decompression failed");
                DEBUG_LOG(ZSTD_getErrorName(decompressed_size));
                ZSTD_freeDCtx(dctx);
                return 0;
            }
            out_pos += decompressed_size;
        } else {
            std::memcpy(output + out_pos, input + ve.in_offset, ve.in_size);
            out_pos += ve.in_size;
        }

        // Паддинг после файла
        if (file_paddings[i] > 0) {
            std::memset(output + out_pos, 0, file_paddings[i]);
            out_pos += file_paddings[i];
        }
    }

    ZSTD_freeDCtx(dctx);

    if (out_pos != output_size) {
        DEBUG_LOG("Error: final size mismatch");
        DEBUG_LOG("Expected: ");
        DEBUG_LOG_NUM(output_size);
        DEBUG_LOG("Actual: ");
        DEBUG_LOG_NUM(out_pos);
        return 0;
    }

    DEBUG_LOG("Conversion successful");
    return out_pos;
}

} // extern "C"