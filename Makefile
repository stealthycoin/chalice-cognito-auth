build:
	python setup.py sdist bdist_wheel

.PHONY: publish
publish:
	twine upload dist/*

.PHONY: clean
clean:
	rm -r build dist
