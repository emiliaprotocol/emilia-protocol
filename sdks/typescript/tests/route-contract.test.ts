import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

interface RouteContract {
  clientMethod: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  path: string;
}

const sdkRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(sdkRoot, '../..');
const clientPath = join(sdkRoot, 'src/client.ts');
const contractPath = join(sdkRoot, 'tests/route-contract.json');
const openApiPaths = [
  join(repositoryRoot, 'openapi.yaml'),
  join(repositoryRoot, 'docs/api/govguard-v1.yaml'),
];

const contract = JSON.parse(readFileSync(contractPath, 'utf8')) as RouteContract[];

function routeKey(route: RouteContract): string {
  return `${route.clientMethod}\u0000${route.method}\u0000${route.path}`;
}

function sorted(routes: RouteContract[]): RouteContract[] {
  return [...routes].sort((left, right) => routeKey(left).localeCompare(routeKey(right)));
}

function enclosingMethodName(node: ts.Node): string {
  for (let current: ts.Node | undefined = node; current; current = current.parent) {
    if (ts.isMethodDeclaration(current) && current.name && ts.isIdentifier(current.name)) {
      return current.name.text;
    }
  }
  throw new Error('SDK request call is not inside a named class method');
}

function placeholderName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (
    ts.isCallExpression(expression)
    && ts.isIdentifier(expression.expression)
    && expression.expression.text === 'encodeURIComponent'
    && expression.arguments.length === 1
  ) {
    return placeholderName(expression.arguments[0]!);
  }
  throw new Error(`Unsupported SDK route interpolation: ${expression.getText()}`);
}

function routePath(expression: ts.Expression): string {
  if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
    return expression.text;
  }
  if (ts.isTemplateExpression(expression)) {
    return expression.head.text + expression.templateSpans
      .map((span) => `{${placeholderName(span.expression)}}${span.literal.text}`)
      .join('');
  }
  throw new Error(`SDK request path must be a literal or template literal: ${expression.getText()}`);
}

function requestMethod(options: ts.Expression | undefined): RouteContract['method'] {
  if (!options || !ts.isObjectLiteralExpression(options)) return 'GET';
  const method = options.properties.find((property) => (
    ts.isPropertyAssignment(property)
    && ts.isIdentifier(property.name)
    && property.name.text === 'method'
  ));
  if (!method || !ts.isPropertyAssignment(method) || !ts.isStringLiteral(method.initializer)) {
    return 'GET';
  }
  return method.initializer.text.toUpperCase() as RouteContract['method'];
}

function extractClientRoutes(): RouteContract[] {
  const sourceFile = ts.createSourceFile(
    clientPath,
    readFileSync(clientPath, 'utf8'),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const routes: RouteContract[] = [];

  function visit(node: ts.Node): void {
    if (
      ts.isCallExpression(node)
      && ts.isPropertyAccessExpression(node.expression)
      && node.expression.expression.kind === ts.SyntaxKind.ThisKeyword
      && node.expression.name.text === 'request'
    ) {
      const pathArgument = node.arguments[0];
      if (!pathArgument) throw new Error('SDK request call is missing a path');
      routes.push({
        clientMethod: enclosingMethodName(node),
        method: requestMethod(node.arguments[1]),
        path: routePath(pathArgument),
      });
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return routes;
}

function runtimeRouteFile(pathTemplate: string): string {
  const relative = pathTemplate
    .replace(/^\//, '')
    .replace(/\{([^}]+)\}/g, '[$1]');
  return join(repositoryRoot, 'app', relative, 'route.ts');
}

function openApiOperations(path: string): Set<string> {
  const operations = new Set<string>();
  let activePath: string | undefined;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const pathMatch = /^  (\/[^:]+):\s*$/.exec(line);
    if (pathMatch) {
      activePath = pathMatch[1];
      continue;
    }
    const methodMatch = /^    (delete|get|patch|post|put):\s*$/.exec(line);
    if (activePath && methodMatch) {
      operations.add(`${methodMatch[1]!.toUpperCase()} ${activePath}`);
    }
  }
  return operations;
}

describe('machine-readable SDK route contract', () => {
  it('enumerates every HTTP request in the public client', () => {
    expect(sorted(extractClientRoutes())).toEqual(sorted(contract));
  });

  it('maps every SDK operation to an implemented app route and verb', () => {
    for (const route of contract) {
      const routeFile = runtimeRouteFile(route.path);
      expect(existsSync(routeFile), `${route.method} ${route.path} has no ${routeFile}`).toBe(true);
      const source = readFileSync(routeFile, 'utf8');
      const handler = new RegExp(`export\\s+(?:async\\s+function|const)\\s+${route.method}\\b`);
      expect(source, `${route.method} ${route.path} has no matching runtime handler`).toMatch(handler);
    }
  });

  it('maps every SDK operation to at least one maintained OpenAPI document', () => {
    const documented = new Set(openApiPaths.flatMap((path) => [...openApiOperations(path)]));
    for (const route of contract) {
      expect(
        documented.has(`${route.method} ${route.path}`),
        `${route.method} ${route.path} is absent from openapi.yaml and docs/api/govguard-v1.yaml`,
      ).toBe(true);
    }
  });
});
