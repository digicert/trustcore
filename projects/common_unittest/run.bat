@echo ON

echo "Running Unit Test..."
pushd ..\..\src\common\test

..\..\..\bin\Debug\common_test.exe %*

popd
