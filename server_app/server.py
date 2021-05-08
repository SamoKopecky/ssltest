from flask import Flask, render_template, request, flash, redirect, url_for
import requests
import json

app = Flask(__name__)
app.debug = True


@app.route('/', methods=['GET', 'POST'])
def index():
    args = ['-u']
    switcher = {
        'nmap_scan': '-ns',
        'nmap_discover': '-nd'
    }
    if request.method == 'POST':
        url = request.form['url']
        args.append(f'{url}')
        args.extend(parse_checkboxes(request.form, switcher))
        tests = request.form['tests']
        if tests != '':
            args.append('-t')
            args.append(tests)
        ports = request.form['ports']
        if ports != '':
            args.append('-p')
            args.append(ports)
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


def beautify_json(json_response):
    return json_response


def parse_checkboxes(request_form, switcher):
    checked = []
    for value in list(switcher.keys()):
        if value not in request_form:
            continue
        if request_form[value] == 'on':
            checked.append(switcher[value])

    return checked
