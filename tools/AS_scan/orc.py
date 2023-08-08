import importlib
from typing import Dict, Any
from lib.result import result
from lib.configuration import configuration
import lib.custom_logger as custom_logger

logger = custom_logger.logger


def run_tool(
    tool_config: Dict[str, Any], config: configuration, res: result, name: str
) -> None:
    """
    Runs a tool specified in the tool_config dictionary.

    :param tool_config: A dictionary containing the configuration for the tool to run.
    :param config: The configuration object for the entire scan.
    :param res: The result object for the entire scan.
    :param name: The name of the scan.
    """
    file = tool_config.get("file")
    recursive_conf = tool_config.get("recursive")
    if file and recursive_conf or file and not recursive_conf:
        # Import the tool's script
        module = importlib.import_module(f"tools.AS_scan.{file}")
        # Check if the tool's script has a main function
        if hasattr(module, "main"):
            # Call the main function of the tool's script
            try:
                tool_res = module.main(config=config, res=res, name=name)
            except Exception as e:
                logger.error(f"Error: Tool '{tool_config}' has failed with error : {e}")
                return

            # Add the tool's result to the main result
            if tool_res and hasattr(tool_res, "result"):
                res.result.update(tool_res.result)
            if not recursive_conf:
                res.export(name)
                res.metadata["last_tool"] = tool_config
        else:
            logger.error(
                f"Error: Tool '{tool_config}' does not have a 'main' function."
            )
    else:
        logger.error(f"Error: Tool '{tool_config}' does not have a 'file' parameter.")


def main(
    config: configuration,
    res: result,
    name: str,
    resume: bool = False,
    recursive: bool = False,
) -> None:
    """
    Main function for the orchestration of the tools to run for the Attack Surface scan.

    :param config: The configuration object for the entire scan.
    :param res: The result object for the entire scan.
    :param name: The name of the scan.
    :param resume: Whether to resume a previous scan.
    :param recursive: Whether to run the scan recursively.
    """
    tools = config.config["TOOLS"]["AS_scan"]
    if not resume:
        for tool, tool_config in tools.items():
            run_tool(tool_config, config, res, name)
    else:
        # resume var contains the name of the tool to resume
        tool_config = tools[resume]
        run_tool(tool_config, config, res, name)
        if not recursive:
            res.export(name)
            res.metadata["last_tool"] = tool_config
        tools_ls = list(tools.keys())
        index = tools_ls.index(resume)
        to_use = tools_ls[index + 1 :]
        for tool in to_use:
            tool_config = tools[tool]
            if recursive and tool_config["recursive"] or not recursive:
                run_tool(tool_config, config, res, name)
                if not recursive:
                    res.export(name)
                    res.metadata["last_tool"] = tool_config
