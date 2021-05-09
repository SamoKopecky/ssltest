from flask import Flask, render_template, request, redirect, url_for
import requests
import json

app = Flask(__name__)
app.debug = True


@app.route('/', methods=['GET', 'POST'])
def index():
    args = ['-u']
    other_options = {
        'nmap_scan': '-ns',
        'nmap_discover': '-nd'
    }
    tests = {
        'heartbleed': '1',
        'ccsinjection': '2',
        'insecrene': '3',
        'poodle': '4',

    }
    if request.method == 'POST':
        url = request.form['url']
        args.append(url)
        args.extend(parse_checkboxes(other_options))
        parsed_tests = parse_checkboxes(tests)
        if len(parsed_tests) > 0:
            args.append('-t')
            args.extend(parsed_tests)
        args.extend(parse_list('ports', '-p'))
        return redirect(url_for('result', args=' '.join(args)))
    return render_template('query_form.html')


@app.route('/result')
@app.route('/result/<args>')
def result(args=None):
    if args is None:
        return ''
    json_response = requests.get(f'http://localhost:5001/?args={args}')
    json_response = json.loads(json_response.content)
    json_response = beautify_json(json_response)
    return render_template('query_result.html', json_response=json_response)


def parse_list(long_key, short_key):
    args = []
    values = request.form[long_key]
    if values != '':
        args.append(short_key)
        args.append(values)
    return args


def beautify_json(json_response):
    return json_response


def parse_checkboxes(switcher):
    checked = []
    for value in list(switcher.keys()):
        if value not in request.form:
            continue
        if request.form[value] == 'on':
            checked.append(switcher[value])
    return checked
