#define FUSE_USE_VERSION 31

#include "config/config_loader.hpp"
#include "config/config_types.hpp"
#include "fuse_operations.hpp"

#include <fuse3/fuse.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

int main(int argc, char *argv[])
{
    // Initialize default logger (console) before config is parsed
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [T:%t] [%^%l%$] [%n] %v");
        auto main_logger = std::make_shared<spdlog::logger>("CacheFS", console_sink);
        spdlog::set_default_logger(main_logger);
        spdlog::set_level(spdlog::level::info);
        spdlog::flush_on(spdlog::level::warn);
    } catch (const spdlog::spdlog_ex &ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    spdlog::info("DistributedCacheFS starting...");

    // --- Basic Argument Parsing ---
    std::vector<std::string> args(argv, argv + argc);
    std::string config_path_str;
    std::string mount_point_str;
    std::vector<char *> fuse_args;
    fuse_args.push_back(argv[0]);  // Program name

    for (size_t i = 1; i < args.size(); ++i) {
        if ((args[i] == "-c" || args[i] == "--config") && i + 1 < args.size()) {
            config_path_str = args[++i];
        } else if (args[i] == "-h" || args[i] == "--help") {
            std::cout << "Usage: " << argv[0] << " <mountpoint> -c <config_file> [FUSE options]\n";
            // TODO: Consider using a proper argument parsing library later (e.g.,
            // CLI11, argparse)
            return EXIT_SUCCESS;
        } else if (!args[i].empty() && args[i][0] == '-') {
            // Pass FUSE options through
            fuse_args.push_back(argv[i]);
            if ((args[i] == "-o" || args[i] == "-d" || args[i] == "-s") && i + 1 < args.size()) {
                fuse_args.push_back(argv[++i]);
            }
        } else if (mount_point_str.empty()) {
            // Assume first non-option is mount point
            mount_point_str = args[i];
            fuse_args.push_back(argv[i]);
        } else {
            spdlog::warn("Ignoring unrecognized argument: {}", args[i]);
        }
    }

    if (mount_point_str.empty()) {
        spdlog::critical("Error: Mount point not specified.");
        std::cerr << "Usage: " << argv[0] << " <mountpoint> -c <config_file> [FUSE options]\n";
        return EXIT_FAILURE;
    }
    if (config_path_str.empty()) {
        spdlog::critical("Error: Config file path not specified (-c <config_file>).");
        return EXIT_FAILURE;
    }

    // --- Load Configuration ---
    std::filesystem::path config_path(config_path_str);
    auto config_result = DistributedCacheFS::Config::loadConfigFromFileVerbose(config_path);

    if (!config_result) {
        spdlog::critical("Error loading configuration: {}", config_result.error());
        return EXIT_FAILURE;
    }

    // --- Initialize Logging Level from Config ---
    spdlog::set_level(config_result.value().global_settings.log_level);
    spdlog::info(
        "Logging level set to: {}",
        spdlog::level::to_string_view(config_result.value().global_settings.log_level)
    );
    spdlog::info("Mounting DistributedCacheFS at: {}", mount_point_str);
    spdlog::info("Using Node ID: {}", config_result.value().node_id);

    // --- Setup Filesystem Context ---
    auto context    = std::make_unique<DistributedCacheFS::FileSystemContext>();
    context->config = std::move(config_result.value());  // Move config into context

    // --- TODO: Initialize StorageManager, NodeManager etc. and add to context
    // --- context->storage_manager = new
    // Storage::StorageManager(context->config.storages);
    // context->storage_manager->initialize_all(); // Example initialization

    // --- Initialize FUSE Operations ---
    // Ensure ops struct has static duration or lives longer than fuse_main
    static fuse_operations fs_ops = DistributedCacheFS::FuseOps::get_fuse_operations();

    // --- Start FUSE Main Loop ---
    spdlog::info("Starting FUSE main loop...");
    int fuse_ret =
        fuse_main(static_cast<int>(fuse_args.size()), fuse_args.data(), &fs_ops, context.get());
    spdlog::info("FUSE main loop finished with code: {}", fuse_ret);

    // --- TODO: Shutdown components before exit ---
    // if (context->storage_manager) {
    //     context->storage_manager->shutdown_all();
    //     delete context->storage_manager;
    // }

    spdlog::info("DistributedCacheFS shutting down.");
    spdlog::shutdown();

    return fuse_ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
