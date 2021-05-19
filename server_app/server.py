from utils import *
from flask import Flask, render_template, request, redirect, url_for
import json
import requests

app = Flask(__name__)


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


@app.route('/result/<args>', methods=['GET', 'POST'])
def result(args=None):
    if request.method == 'POST':
        return redirect(url_for('index'))
    if args is None:
        return ''
    response = requests.get(f'http://localhost:5001/?args={args}')
    json_data = json.loads(response.content, object_hook=translate_keys)
    remove_invalid_values(json_data)
    return render_template('query_result.html', json_response=json_data)


if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0')
