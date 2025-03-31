#define FUSE_USE_VERSION 31

#include "config/config_loader.hpp"
#include "config/config_types.hpp"
#include "fuse_operations.hpp"

#include <fuse3/fuse.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

int main(int argc, char *argv[])
{
    // Command Line argument parsing
    CLI::App app{"DistributedCacheFS - A FUSE-based distributed cache filesystem."};
    app.allow_extras();

    std::string config_path_str;
    std::string mount_point_str;

    app.add_option("-c,--config", config_path_str, "Path to the configuration JSON file")
        ->required()
        ->check(CLI::ExistingFile);

    app.add_option("mountpoint", mount_point_str, "Path to the FUSE mount point")->required();

    app.set_version_flag(
        "-v,--version", "DistributedCacheFS version 0.1.0"
    );  // TODO: Take this from cmake

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    // Initialize default logger (console) before config is parsed
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [T:%t] [%^%l%$] [%n] %v");
        auto main_logger = std::make_shared<spdlog::logger>("DistributedCacheFS", console_sink);
        spdlog::set_default_logger(main_logger);
        spdlog::set_level(spdlog::level::info);
        spdlog::flush_on(spdlog::level::warn);
    } catch (const spdlog::spdlog_ex &ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    spdlog::info("DistributedCacheFS starting...");

    // Load Configuration
    std::filesystem::path config_path(config_path_str);
    auto config_result = DistributedCacheFS::Config::loadConfigFromFileVerbose(config_path);

    if (!config_result) {
        spdlog::critical("Error loading configuration: {}", config_result.error());
        return EXIT_FAILURE;
    }

    // Initialize Logging Level from Config
    spdlog::set_level(config_result.value().global_settings.log_level);
    spdlog::info(
        "Logging level set to: {}",
        spdlog::level::to_string_view(config_result.value().global_settings.log_level)
    );
    spdlog::info("Mounting DistributedCacheFS at: {}", mount_point_str);
    spdlog::info("Using Node ID: {}", config_result.value().node_id);

    // Setup Filesystem Context
    auto context    = std::make_unique<DistributedCacheFS::FileSystemContext>();
    context->config = std::move(config_result.value());

    // TODO: Initialize StorageManager, NodeManager etc. and add to context

    // Construct arguments for fuse_main
    std::vector<char *> fuse_argv;
    fuse_argv.push_back(argv[0]);  // Program name

    std::vector<std::string> remaining_args_storage = app.remaining();
    for (const auto &arg : remaining_args_storage) {
        fuse_argv.push_back(const_cast<char *>(arg.c_str()));
    }
    fuse_argv.push_back(const_cast<char *>(mount_point_str.c_str()));

    spdlog::debug("Arguments passed to fuse_main:");
    for (const char *arg : fuse_argv) {
        if (arg) {
            spdlog::debug("  '{}'", arg);
        }
    }
    // Initialize FUSE Operations
    // Ensure ops struct has static duration or lives longer than fuse_main
    static fuse_operations fs_ops = DistributedCacheFS::FuseOps::get_fuse_operations();

    // Start FUSE Main Loop
    spdlog::info("Starting FUSE main loop...");
    int fuse_ret =
        fuse_main(static_cast<int>(fuse_argv.size()), fuse_argv.data(), &fs_ops, context.get());
    spdlog::info("FUSE main loop finished with code: {}", fuse_ret);

    // TODO: Shutdown components before exit

    spdlog::info("DistributedCacheFS shutting down.");
    spdlog::shutdown();

    return fuse_ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
