import os
import sys
import urllib.request

ASSETS = [
    (
        'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css',
        os.path.join('static', 'vendor', 'bootstrap', 'css', 'bootstrap.min.css'),
    ),
    (
        'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
        os.path.join('static', 'vendor', 'bootstrap', 'js', 'bootstrap.bundle.min.js'),
    ),
    (
        'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css',
        os.path.join('static', 'vendor', 'bootstrap-icons', 'bootstrap-icons.css'),
    ),
]

def ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def download(url: str, dest: str):
    print(f'Downloading {url} -> {dest}')
    ensure_dir(dest)
    urllib.request.urlretrieve(url, dest)

def patch_bootstrap_icons_css(css_path: str):
    """把 icons CSS 中的字体 URL 改为相对本地路径。"""
    if not os.path.exists(css_path):
        return
    with open(css_path, 'r', encoding='utf-8') as f:
        css = f.read()
    # bootstrap-icons.css 默认引用 ../fonts/bootstrap-icons.woff2 等
    # 我们保持目录结构：static/vendor/bootstrap-icons/fonts/
    # 因此无需替换；如果CDN绝对路径，做一次替换为相对路径
    css = css.replace('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/', '')
    with open(css_path, 'w', encoding='utf-8') as f:
        f.write(css)

def main():
    # 基础文件
    for url, dest in ASSETS:
        try:
            download(url, dest)
        except Exception as e:
            print(f'Failed: {url} -> {dest}: {e}', file=sys.stderr)

    # bootstrap-icons 字体文件（两种常见格式）
    fonts = [
        'bootstrap-icons.woff2',
        'bootstrap-icons.woff',
    ]
    for fn in fonts:
        url = f'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/fonts/{fn}'
        dest = os.path.join('static', 'vendor', 'bootstrap-icons', 'fonts', fn)
        try:
            download(url, dest)
        except Exception as e:
            print(f'Failed font: {url} -> {dest}: {e}', file=sys.stderr)

    # 修补CSS（如需）
    patch_bootstrap_icons_css(os.path.join('static', 'vendor', 'bootstrap-icons', 'bootstrap-icons.css'))
    print('Assets fetched.')

if __name__ == '__main__':
    main()

