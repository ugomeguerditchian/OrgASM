import jinja2
from lib.result import result
import lib.generics as gen
import importlib
import os
import web.mapper

dir = os.path.dirname(__file__)

# import all file inside the /mapper folder
for file in os.listdir("web/mapper"):
    if file.endswith(".py"):
        importlib.import_module(f"web.mapper.{file[:-3]}")


def head():
    css = ""
    path = os.path.join(dir, "style.css")
    if os.path.exists(path):
        with open(path, "r") as f:
            css = f.read()
    template = jinja2.Template(
        """
        <!doctype html>
            <head>
                <meta charset="utf-8">
                <title>OrgASM Result</title>
                <style>
                {{ css }}
                </style>
                <link rel="stylesheet" href="https://unpkg.com/bootstrap-table@1.16.0/dist/bootstrap-table.min.css">
                <script defer src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>
                <link rel="stylesheet" href="https://cdn.datatables.net/1.13.3/css/jquery.dataTables.min.css" />
                <script defer src="https://cdn.datatables.net/1.13.3/js/jquery.dataTables.min.js"></script>
                
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.js" integrity="sha512-6DC1eE3AWg1bgitkoaRM1lhY98PxbMIbhgYCGV107aZlyzzvaWCW1nJW2vDuYQm06hXrW0As6OGKcIaAVWnHJw==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
                <link href="https://cdn.datatables.net/v/bs5/dt-1.13.4/r-2.4.1/rg-1.3.1/rr-1.3.3/sc-2.1.1/sb-1.4.1/datatables.min.css" rel="stylesheet"/>
                <script src="https://cdn.datatables.net/v/bs5/dt-1.13.4/r-2.4.1/rg-1.3.1/rr-1.3.3/sc-2.1.1/sb-1.4.1/datatables.min.js"></script>
            </head>
            
    """
    )
    return template.render(css=css)


def start_body():
    with open(os.path.join(dir, "ascii.txt"), "r") as f:
        ascii = f.read()
    template = jinja2.Template(
        """
        <body>
            <div d-flex align-items-center justify-content-center>
                <div class="container-lg">
                        <h2 class="fs-2" style="padding:2rem 0">
                            <a id="logo" href="https://github.com/ugomeguerditchian/OrgASM">
                                {% set lines = ascii.split("\n") %}
                                {% for line in lines %}
                                    {% set line_sp = line.replace(" ","&nbsp;") %}
                                    <div>{{ line_sp|safe }}</div>
                                {% endfor %}
                            </a>
                        </h2>
                    <div>Version : 2.0</div>
                </div>
            </div>
        """
    )
    return template.render(ascii=ascii)


def end_body():
    return """
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
        <script>
            $(document).ready(function () {
                $('table.display').DataTable({responsive: true});
            });
        </script>
        </body>
        """


def start_tab(name: str) -> str:
    """
    Create a new tab
    """
    template = jinja2.Template(
        """
            <div class="tab-pane fade"
                id="nav-{{ name | replace(' ', '') }}"
                role="tabpanel"
                aria-labelledby="nav-{{ name| replace(' ', '') }}-tab"
                tabindex="0">
        """
    )
    return template.render(name=name)


def end_tab() -> str:
    """
    End a tab
    """
    return "</div>"


def new_table(this_dict: dict, columns: list, name: str) -> str:
    """
    Create a new table from the given dict.

    this_dict has to be in the following format:
    {
        "raw1_name": columns1:{[values]}, columns2:{[values]}, columns3:{[values]},
        "raw2_name": columns1:{[values]}, columns2:{[values]}, columns3:{[values]},
    }

    can be :
    this_dict = {
        '192.168.1.1': {'ports': ['80', '443'], 'fqdns': ['test.com', 'test2.com']},
        '192.168.1.2': {'ports': ['80', '443'], 'fqdns': ['test.com', 'test2.com']},
    """
    template = jinja2.Template(
        """
        <h2 class="fs-2">{{ name }}</h2>
        <div style="overflow-x:scroll">
            <table id="{{ name | replace(' ', '') }}" class="display responsive nowrap" style="width:100%">
                <thead>
                    <tr>
                        {% for column in columns %}
                            <th>{{ column }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for raw in this_dict %}
                        <tr>
                            <td>{{ raw }}</td>
                            {% for column in columns[1:] %}
                                <td>
                                    {% for value in this_dict[raw][column] %}
                                        {{ value }}<br>
                                    {% endfor %}
                                </td>
                            {% endfor %}
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    """,
        autoescape=True,
    )
    return template.render(this_dict=this_dict, columns=columns, name=name)


def new_table_multi(this_dict: dict, collumns: list, name: str) -> str:
    """
    Create a new table from the given dict.

    this_dict has to be in the following format:
    {
        "ip1": {[{Name:name, Severity:severity...}, {Name:name, Severity:severity...}, ...]}
        "ip2": {[{Name:name, Severity:severity...}, {Name:name, Severity:severity...}, ...]}
        "fqdn": {[{Name:name, Severity:severity...}, {Name:name, Severity:severity...}, ...]}
    }
    """

    template = jinja2.Template(
        """
        <h2 class="fs-2"> {{ name }}</h2>
        <div style="overflow-x:scroll">
            <table id="{{ name | replace(' ', '') }}" class="display responsive nowrap" style="width:100%">
                <thead>
                    <tr>
                        {% for collumn in collumns %}
                            <th>{{ collumn }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for ip in this_dict %}
                        {% for vuln in this_dict[ip] %}
                            <tr>
                                <td>{{ ip }}</td>
                                {% for collumn in collumns[1:] %}
                                    {% if collumn.lower() not in vuln %}
                                        <td></td>
                                    {% else %}
                                        <td>{{ vuln[collumn.lower()] }}</td>
                                    {% endif %}
                                {% endfor %}
                            </tr>
                        {% endfor %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
    """,
        autoescape=True,
    )
    return template.render(this_dict=this_dict, collumns=collumns, name=name)


def new_list(this_list: list, name: str) -> str:
    """
    Create a new list from the given list.
    """
    template = jinja2.Template(
        """
        <h2 class="fs-2">{{ name }}</h2>
        <ul>
            {% for item in this_list %}
                <li>{{ item }}</li>
            {% endfor %}
        </ul>
    """,
        autoescape=True,
    )
    return template.render(this_list=this_list, name=name)


def nav_creator(tab_list: list) -> str:
    """
    list contains all the tab names
    """
    template = jinja2.Template(
        """
        <div class="container-lg">
            <nav>
                <ul class="nav nav-tabs"
                     id="nav-tab"
                     role="tablist">
                    {% for tab in tab_list %}
                        <li class="nav-item" role="presentation">
                            <button class="nav-link"
                                id="nav-{{ tab | replace(' ', '')}}-tab"
                                data-bs-toggle="tab"
                                data-bs-target="#nav-{{ tab | replace(' ', '')}}"
                                type="button"
                                role="tab"
                                aria-controls="nav-{{ tab | replace(' ', '')}}"
                                aria-selected="false">{{ tab }}
                            </button>
                        </li>
                    {% endfor %}
                </ul>
            </nav>
        </div>
    """,
        autoescape=True,
    )
    return template.render(tab_list=tab_list)


def start_tab_content() -> str:
    """
    Start the tab content
    """
    template = jinja2.Template(
        """
        <div class="tab-content container-lg" id="nav-tabContent">
    """
    )
    return template.render()


def end_tab_content() -> str:
    """
    End the tab content
    """
    template = jinja2.Template(
        """
        </div>
    """
    )
    return template.render()


def get_tools_order(config: gen.configuration) -> list:
    """
    Return a dict. As the tool can "depends_on" other tool the dict will be like:
    {
        "tool1": ["tool2", "tool3"],
        "tool5": ["tool4"],
        "tool6": []
    }
    """
    order = {}
    for tool in config.config["WEB"]:
        if tool == "activate":
            continue
        if tool not in order and config.config["WEB"][tool]["depends_on"] == None:
            order[tool] = []
        for tool2 in config.config["WEB"]:
            if config.config["WEB"][tool]["depends_on"] != None:
                if tool2 == config.config["WEB"][tool]["depends_on"]:
                    order[tool2].append(tool)
    return order


def get_tools_tabs(config: gen.configuration) -> list:
    """
    Return a list of all the tabs
    """
    tabs = []
    for tool in config.config["WEB"]:
        if (
            tool != "activate"
            and "tab" in config.config["WEB"][tool]
            and config.config["WEB"][tool]["tab"] not in tabs
        ):
            tabs.append(config.config["WEB"][tool]["tab"])
    return tabs


def main(config: gen.configuration, result: result):
    website_code = head()
    tabs = get_tools_tabs(config)
    website_code += start_body()
    website_code += nav_creator(tabs)
    config_data = config.config["WEB"]
    tools_order = get_tools_order(config)
    website_code += start_tab_content()
    for tab in tabs:
        website_code += start_tab(tab)
        for tool, childs in tools_order.items():
            if (
                tool != "activate"
                and "tab" in config.config["WEB"][tool]
                and tab != config.config["WEB"][tool]["tab"]
            ):
                continue

            # use the mapper inside config_data[tool]["mapper"]
            # use main of this mapper (mapper.main(result))
            mapper = config_data[tool]["mapper"]
            if (
                tool in ["initial_scan", "deads"]
                or tool not in ["initial_scan", "deads"]
                and config.config["TOOLS"][tool]["activate"]
            ):
                data = eval(f"web.mapper.{mapper}.main(result)")
                for child in childs:
                    data.update(
                        eval(
                            f"web.mapper.{config_data[child]['mapper']}.main(data, result)"
                        )
                    )
                if config_data[tool]["style"] == "table":
                    collumns = config_data[tool]["collumns"]
                    for child in childs:
                        if "collumns" in config_data[child]:
                            collumns += config_data[child]["collumns"]
                    website_code += new_table(data, collumns, config_data[tool]["name"])
                elif config_data[tool]["style"] == "table_multi":
                    collumns = config_data[tool]["collumns"]
                    for child in childs:
                        if "collumns" in config_data[child]:
                            collumns += config_data[child]["collumns"]
                    website_code += new_table_multi(
                        data, collumns, config_data[tool]["name"]
                    )
                elif config_data[tool]["style"] == "list":
                    website_code += new_list(data, config_data[tool]["name"])
                else:
                    raise Exception("Error: Unknown type in config file")
        website_code += end_tab()
    website_code += end_tab_content()
    website_code += end_body()
    return website_code
